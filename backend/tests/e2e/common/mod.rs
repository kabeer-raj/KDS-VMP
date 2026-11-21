#![allow(dead_code, unused_imports)]

pub mod assertions;
pub mod auth_helpers;
pub mod client;
pub mod mock_zap;

pub use assertions::*;
pub use auth_helpers::*;
pub use client::*;
pub use mock_zap::*;
pub use crate::assert_err_code;

pub use shared_types::app::{
    AppTrendPoint, AppTrendsResponse, ApplicationResponse, ConfigureAuthRequest,
    CreateApplicationRequest, UpdateApplicationRequest,
};
pub use shared_types::auth::{
    ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse, LoginRequest, RefreshTokenRequest,
};
pub use shared_types::enums::{
    AppCriticality, AppEnvironment, DiffClassification, RemediationStatus, ScanStatus, ScanType,
    SeverityLevel,
};
pub use shared_types::scan::{
    ScanComparisonResponse, ScanDiffSummary, ScanResponse, SeverityCounts, TriggerScanRequest,
};
pub use shared_types::events::{
    ScanCompletedEvent, ScanFailedEvent, ScanProgressEvent, WsServerEvent,
};
pub use shared_types::vuln::{
    AddCommentRequest, BulkUpdateResponse, BulkUpdateVulnsRequest, HttpEvidence,
    RemediationAuditLogResponse, UpdateVulnerabilityRequest, VulnerabilityDetail,
    VulnerabilitySummary,
};
pub use shared_types::common::PaginatedResponse;
pub use scan_worker::ScanWorkerEngine;
pub use core_domain::deduplicator::{generate_fingerprint, normalize_url_path};
pub use core_domain::diff_engine::{
    diff_scans, DiffItem, FindingFingerprint, FindingLifecycleState, ScanDiffResult,
};

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

// -----------------------------------------------------------------------------
// DTOs for Auth
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfile {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: UserRole,
    pub is_active: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserProfile,
}

// -----------------------------------------------------------------------------
// In-Memory Repository Models & Implementations
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub password_hash: String,
    pub role: UserRole,
    pub is_active: bool,
    #[serde(default)]
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl UserRecord {
    pub fn to_profile(&self) -> UserProfile {
        UserProfile {
            id: self.id,
            email: self.email.clone(),
            full_name: self.full_name.clone(),
            role: self.role,
            is_active: self.is_active,
            last_login_at: self.last_login_at,
            created_at: self.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_revoked: bool,
}

impl ApiKeyRecord {
    pub fn to_response(&self) -> ApiKeyResponse {
        ApiKeyResponse {
            id: self.id,
            name: self.name.clone(),
            key_prefix: self.key_prefix.clone(),
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            created_at: self.created_at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RefreshTokenRecord {
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Default, Clone)]
pub struct InMemoryUserRepo {
    users: Arc<RwLock<HashMap<Uuid, UserRecord>>>,
    api_keys: Arc<RwLock<HashMap<String, ApiKeyRecord>>>, // keyed by key_hash
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshTokenRecord>>>, // keyed by token
}

impl InMemoryUserRepo {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert_user(
        &self,
        id: Uuid,
        email: &str,
        full_name: &str,
        password_hash: &str,
        role: UserRole,
        is_active: bool,
    ) -> UserRecord {
        let user = UserRecord {
            id,
            email: email.to_string(),
            full_name: full_name.to_string(),
            password_hash: password_hash.to_string(),
            role,
            is_active,
            last_login_at: None,
            created_at: Utc::now(),
        };
        let mut map = self.users.write().await;
        map.insert(id, user.clone());
        user
    }

    pub async fn find_by_email(&self, email: &str) -> Option<UserRecord> {
        let map = self.users.read().await;
        map.values()
            .find(|u| u.email.eq_ignore_ascii_case(email))
            .cloned()
    }

    pub async fn find_by_id(&self, id: Uuid) -> Option<UserRecord> {
        let map = self.users.read().await;
        map.get(&id).cloned()
    }

    pub async fn update_last_login(&self, user_id: Uuid) {
        let mut map = self.users.write().await;
        if let Some(user) = map.get_mut(&user_id) {
            user.last_login_at = Some(Utc::now());
        }
    }

    pub async fn set_active_status(&self, user_id: Uuid, is_active: bool) {
        let mut map = self.users.write().await;
        if let Some(user) = map.get_mut(&user_id) {
            user.is_active = is_active;
        }
    }

    pub async fn insert_api_key(
        &self,
        id: Uuid,
        user_id: Uuid,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> ApiKeyRecord {
        let key = ApiKeyRecord {
            id,
            user_id,
            name: name.to_string(),
            key_prefix: key_prefix.to_string(),
            key_hash: key_hash.to_string(),
            expires_at,
            last_used_at: None,
            created_at: Utc::now(),
            is_revoked: false,
        };
        let mut map = self.api_keys.write().await;
        map.insert(key_hash.to_string(), key.clone());
        key
    }

    pub async fn find_api_key_by_hash(&self, key_hash: &str) -> Option<ApiKeyRecord> {
        let map = self.api_keys.read().await;
        map.get(key_hash).filter(|k| !k.is_revoked).cloned()
    }

    pub async fn update_api_key_last_used(&self, key_hash: &str) {
        let mut map = self.api_keys.write().await;
        if let Some(k) = map.get_mut(key_hash) {
            k.last_used_at = Some(Utc::now());
        }
    }

    pub async fn list_api_keys_for_user(&self, user_id: Uuid) -> Vec<ApiKeyRecord> {
        let map = self.api_keys.read().await;
        map.values()
            .filter(|k| k.user_id == user_id && !k.is_revoked)
            .cloned()
            .collect()
    }

    pub async fn delete_api_key(&self, key_id: Uuid) -> bool {
        let mut map = self.api_keys.write().await;
        let hash_opt = map
            .values()
            .find(|k| k.id == key_id && !k.is_revoked)
            .map(|k| k.key_hash.clone());
        if let Some(h) = hash_opt {
            if let Some(k) = map.get_mut(&h) {
                k.is_revoked = true;
            }
            true
        } else {
            false
        }
    }

    pub async fn store_refresh_token(&self, user_id: Uuid, token: &str, ttl_days: i64) {
        let mut map = self.refresh_tokens.write().await;
        map.insert(
            token.to_string(),
            RefreshTokenRecord {
                user_id,
                token: token.to_string(),
                expires_at: Utc::now() + Duration::days(ttl_days),
            },
        );
    }

    pub async fn validate_refresh_token(
        &self,
        token: &str,
    ) -> Result<Uuid, (StatusCode, &'static str, &'static str)> {
        if !token.starts_with("refresh_") {
            return Err((
                StatusCode::UNAUTHORIZED,
                "INVALID_REFRESH_TOKEN",
                "Malformed refresh token",
            ));
        }
        let map = self.refresh_tokens.read().await;
        let rec = map.get(token).ok_or((
            StatusCode::UNAUTHORIZED,
            "INVALID_REFRESH_TOKEN",
            "Refresh token not found or revoked",
        ))?;
        if rec.expires_at < Utc::now() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "REFRESH_TOKEN_EXPIRED",
                "Refresh token has expired",
            ));
        }
        Ok(rec.user_id)
    }

    pub async fn rotate_refresh_token(
        &self,
        old_token: &str,
        new_token: &str,
        ttl_days: i64,
    ) -> Result<Uuid, (StatusCode, &'static str, &'static str)> {
        if !old_token.starts_with("refresh_") {
            return Err((
                StatusCode::UNAUTHORIZED,
                "INVALID_REFRESH_TOKEN",
                "Malformed refresh token",
            ));
        }
        let mut map = self.refresh_tokens.write().await;
        let rec = map.remove(old_token).ok_or((
            StatusCode::UNAUTHORIZED,
            "INVALID_REFRESH_TOKEN",
            "Refresh token not found or revoked",
        ))?;
        if rec.expires_at < Utc::now() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "REFRESH_TOKEN_EXPIRED",
                "Refresh token has expired",
            ));
        }
        let user_id = rec.user_id;
        map.insert(
            new_token.to_string(),
            RefreshTokenRecord {
                user_id,
                token: new_token.to_string(),
                expires_at: Utc::now() + Duration::days(ttl_days),
            },
        );
        Ok(user_id)
    }

    pub async fn revoke_refresh_token(&self, token: &str) -> bool {
        let mut map = self.refresh_tokens.write().await;
        map.remove(token).is_some()
    }

    pub async fn revoke_all_refresh_tokens_for_user(&self, user_id: Uuid) {
        let mut map = self.refresh_tokens.write().await;
        map.retain(|_, v| v.user_id != user_id);
    }
}

#[derive(Default, Clone)]
pub struct InMemoryAppRepo {
    apps: Arc<RwLock<HashMap<Uuid, ApplicationResponse>>>,
    auth_configs: Arc<RwLock<HashMap<Uuid, serde_json::Value>>>,
}

impl InMemoryAppRepo {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert_app(&self, app: ApplicationResponse) {
        let mut map = self.apps.write().await;
        map.insert(app.id, app);
    }

    pub async fn find_by_id(&self, id: Uuid) -> Option<ApplicationResponse> {
        let map = self.apps.read().await;
        map.get(&id).cloned()
    }

    pub async fn find_by_name_and_env(
        &self,
        name: &str,
        env: AppEnvironment,
    ) -> Option<ApplicationResponse> {
        let map = self.apps.read().await;
        map.values()
            .find(|a| a.name.eq_ignore_ascii_case(name) && a.environment == env)
            .cloned()
    }

    pub async fn list_apps(&self) -> Vec<ApplicationResponse> {
        let map = self.apps.read().await;
        map.values().cloned().collect()
    }

    pub async fn delete_app(&self, id: Uuid) -> bool {
        let mut map = self.apps.write().await;
        let mut auths = self.auth_configs.write().await;
        auths.remove(&id);
        map.remove(&id).is_some()
    }

    pub async fn update_app(
        &self,
        id: Uuid,
        req: UpdateApplicationRequest,
    ) -> Option<ApplicationResponse> {
        let mut map = self.apps.write().await;
        let app = map.get_mut(&id)?;
        if let Some(name) = req.name {
            app.name = name;
        }
        if let Some(desc) = req.description {
            app.description = Some(desc);
        }
        if let Some(env) = req.environment {
            app.environment = env;
        }
        if let Some(crit) = req.criticality {
            app.criticality = crit;
        }
        if let Some(team) = req.team_name {
            app.team_name = Some(team);
        }
        if let Some(inc) = req.include_regexes {
            app.include_regexes = inc;
        }
        if let Some(exc) = req.exclude_regexes {
            app.exclude_regexes = exc;
        }
        if let Some(cron) = req.cron_schedule {
            app.cron_schedule = Some(cron);
        }
        Some(app.clone())
    }

    pub async fn set_auth_configured(
        &self,
        id: Uuid,
        configured: bool,
        auth_data: Option<serde_json::Value>,
    ) -> bool {
        let mut map = self.apps.write().await;
        let app = match map.get_mut(&id) {
            Some(a) => a,
            None => return false,
        };
        app.has_auth_configured = configured;
        if let Some(data) = auth_data {
            let mut auths = self.auth_configs.write().await;
            auths.insert(id, data);
        }
        true
    }

    pub async fn update_risk_posture(&self, id: Uuid, risk_score: f64) {
        let mut map = self.apps.write().await;
        if let Some(app) = map.get_mut(&id) {
            app.latest_risk_score = risk_score;
            app.last_scanned_at = Some(Utc::now());
        }
    }

    pub async fn get_trends(
        &self,
        app_id: Uuid,
        scan_repo: &InMemoryScanRepo,
        _days: Option<i64>,
    ) -> Option<AppTrendsResponse> {
        let map = self.apps.read().await;
        if !map.contains_key(&app_id) {
            return None;
        }
        let scans = scan_repo.list_scans_for_app(app_id).await;
        let mut completed_scans: Vec<_> = scans
            .into_iter()
            .filter(|s| s.status == ScanStatus::Completed)
            .collect();
        completed_scans.sort_by_key(|s| s.completed_at);

        let data_points = completed_scans
            .into_iter()
            .map(|s| AppTrendPoint {
                timestamp: s.completed_at.unwrap_or_else(Utc::now),
                scan_id: Some(s.id),
                risk_score: s.overall_risk_score,
                severity_counts: s.severity_counts,
            })
            .collect();

        Some(AppTrendsResponse {
            app_id,
            data_points,
        })
    }
}

#[derive(Default, Clone)]
pub struct InMemoryScanRepo {
    pub scans: Arc<RwLock<HashMap<Uuid, ScanResponse>>>,
    pub findings: Arc<RwLock<HashMap<Uuid, Vec<serde_json::Value>>>>,
}

impl InMemoryScanRepo {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert_scan(&self, scan: ScanResponse) {
        let mut map = self.scans.write().await;
        map.insert(scan.id, scan);
    }

    pub async fn get_scan(&self, id: Uuid) -> Option<ScanResponse> {
        let map = self.scans.read().await;
        map.get(&id).cloned()
    }

    pub async fn list_scans_for_app(&self, app_id: Uuid) -> Vec<ScanResponse> {
        let map = self.scans.read().await;
        map.values().filter(|s| s.application_id == app_id).cloned().collect()
    }

    pub async fn insert_findings(&self, scan_id: Uuid, findings: Vec<serde_json::Value>) {
        let mut map = self.findings.write().await;
        map.insert(scan_id, findings);
    }

    pub async fn get_findings(&self, scan_id: Uuid) -> Option<Vec<serde_json::Value>> {
        let map = self.findings.read().await;
        map.get(&scan_id).cloned()
    }

    pub async fn insert_scan_findings(&self, scan_id: Uuid, findings: Vec<VulnerabilitySummary>) {
        let values: Vec<serde_json::Value> = findings
            .into_iter()
            .map(|f| serde_json::to_value(f).unwrap())
            .collect();
        self.insert_findings(scan_id, values).await;
    }

    pub async fn list_findings_for_scan(&self, scan_id: Uuid) -> Vec<VulnerabilitySummary> {
        let vals = self.get_findings(scan_id).await.unwrap_or_default();
        vals.into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect()
    }

    pub async fn has_active_scan(&self, app_id: Uuid) -> bool {
        let map = self.scans.read().await;
        map.values().any(|s| {
            s.application_id == app_id
                && matches!(
                    s.status,
                    ScanStatus::Queued
                        | ScanStatus::Spidering
                        | ScanStatus::ActiveScanning
                        | ScanStatus::Ingesting
                )
        })
    }

    pub async fn cancel_scan(&self, scan_id: Uuid) -> Result<ScanResponse, &'static str> {
        let mut map = self.scans.write().await;
        match map.get_mut(&scan_id) {
            None => Err("SCAN_NOT_FOUND"),
            Some(scan) => match scan.status {
                ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled => {
                    Err("SCAN_CANNOT_BE_CANCELLED")
                }
                _ => {
                    scan.status = ScanStatus::Cancelled;
                    scan.completed_at = Some(Utc::now());
                    Ok(scan.clone())
                }
            },
        }
    }

    pub async fn update_status(
        &self,
        id: Uuid,
        status: ScanStatus,
        progress_percent: u8,
        error_message: Option<String>,
    ) {
        let mut map = self.scans.write().await;
        if let Some(scan) = map.get_mut(&id) {
            scan.status = status;
            scan.progress_percent = progress_percent;
            scan.error_message = error_message;
            if (status == ScanStatus::ActiveScanning || status == ScanStatus::Spidering)
                && scan.started_at.is_none()
            {
                scan.started_at = Some(Utc::now());
            }
        }
    }

    pub async fn complete_scan(
        &self,
        id: Uuid,
        counts: SeverityCounts,
        diff: ScanDiffSummary,
        overall_risk_score: f64,
    ) {
        let mut map = self.scans.write().await;
        if let Some(scan) = map.get_mut(&id) {
            scan.status = ScanStatus::Completed;
            scan.progress_percent = 100;
            scan.severity_counts = counts;
            scan.diff_summary = diff;
            scan.overall_risk_score = overall_risk_score;
            scan.completed_at = Some(Utc::now());
        }
    }

    pub async fn get_previous_completed_scan(
        &self,
        app_id: Uuid,
        current_scan_id: Uuid,
    ) -> Option<ScanResponse> {
        let map = self.scans.read().await;
        map.values()
            .filter(|s| {
                s.application_id == app_id
                    && s.id != current_scan_id
                    && s.status == ScanStatus::Completed
            })
            .max_by_key(|s| s.completed_at)
            .cloned()
    }
}

// -----------------------------------------------------------------------------
// Job Queue & Cron Simulation Helpers
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ScanJob {
    pub scan_id: Uuid,
    pub application_id: Uuid,
    pub target_url: String,
    pub scan_type: ScanType,
    pub custom_headers: Option<HashMap<String, String>>,
}

#[derive(Default, Clone)]
pub struct InMemoryScanJobQueue {
    pub queue: Arc<RwLock<VecDeque<ScanJob>>>,
}

impl InMemoryScanJobQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn enqueue(&self, job: ScanJob) {
        let mut q = self.queue.write().await;
        q.push_back(job);
    }

    pub async fn dequeue(&self) -> Option<ScanJob> {
        let mut q = self.queue.write().await;
        q.pop_front()
    }

    pub async fn len(&self) -> usize {
        let q = self.queue.read().await;
        q.len()
    }

    pub async fn is_empty(&self) -> bool {
        let q = self.queue.read().await;
        q.is_empty()
    }
}

#[derive(Default, Clone)]
pub struct InMemoryVulnRepo {
    vulns: Arc<RwLock<HashMap<Uuid, serde_json::Value>>>,
}

impl InMemoryVulnRepo {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert_vuln(&self, id: Uuid, val: serde_json::Value) {
        let mut map = self.vulns.write().await;
        map.insert(id, val);
    }

    pub async fn get_vuln(&self, id: Uuid) -> Option<serde_json::Value> {
        let map = self.vulns.read().await;
        map.get(&id).cloned()
    }
}

#[derive(Default, Clone)]
pub struct InMemoryAuditLogRepo {
    logs: Arc<RwLock<Vec<serde_json::Value>>>,
}

impl InMemoryAuditLogRepo {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert_log(&self, val: serde_json::Value) {
        let mut list = self.logs.write().await;
        list.push(val);
    }

    pub async fn get_logs(&self) -> Vec<serde_json::Value> {
        let list = self.logs.read().await;
        list.clone()
    }
}

#[derive(Clone)]
pub struct InMemoryPubSub {
    sender: broadcast::Sender<String>,
}

impl InMemoryPubSub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(128);
        Self { sender }
    }

    pub fn publish(&self, message: &str) -> usize {
        self.sender.send(message.to_string()).unwrap_or(0)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.sender.subscribe()
    }
}

// -----------------------------------------------------------------------------
// TestApp Context & State
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct SharedAppState {
    pub user_repo: Arc<InMemoryUserRepo>,
    pub app_repo: Arc<InMemoryAppRepo>,
    pub scan_repo: Arc<InMemoryScanRepo>,
    pub vuln_repo: Arc<InMemoryVulnRepo>,
    pub audit_repo: Arc<InMemoryAuditLogRepo>,
    pub pubsub: Arc<InMemoryPubSub>,
    pub mock_zap: Arc<MockZapClient>,
    pub jwt_secret: String,
}

pub struct TestApp {
    pub client: TestClient,
    pub router: Router,
    pub state: SharedAppState,
    pub user_repo: Arc<InMemoryUserRepo>,
    pub app_repo: Arc<InMemoryAppRepo>,
    pub scan_repo: Arc<InMemoryScanRepo>,
    pub vuln_repo: Arc<InMemoryVulnRepo>,
    pub audit_repo: Arc<InMemoryAuditLogRepo>,
    pub pubsub: Arc<InMemoryPubSub>,
    pub mock_zap: Arc<MockZapClient>,
    pub jwt_secret: String,
}

impl TestApp {
    pub async fn new() -> Self {
        let jwt_secret = "test_jwt_secret_key_appsec_platform_2026_super_secure".to_string();

        let user_repo = Arc::new(InMemoryUserRepo::new());
        let app_repo = Arc::new(InMemoryAppRepo::new());
        let scan_repo = Arc::new(InMemoryScanRepo::new());
        let vuln_repo = Arc::new(InMemoryVulnRepo::new());
        let audit_repo = Arc::new(InMemoryAuditLogRepo::new());
        let pubsub = Arc::new(InMemoryPubSub::new());
        let mock_zap = Arc::new(MockZapClient::new());

        let state = SharedAppState {
            user_repo: user_repo.clone(),
            app_repo: app_repo.clone(),
            scan_repo: scan_repo.clone(),
            vuln_repo: vuln_repo.clone(),
            audit_repo: audit_repo.clone(),
            pubsub: pubsub.clone(),
            mock_zap: mock_zap.clone(),
            jwt_secret: jwt_secret.clone(),
        };

        let router = build_router(state.clone());
        let client = TestClient::new(router.clone());

        let app = Self {
            client,
            router,
            state,
            user_repo,
            app_repo,
            scan_repo,
            vuln_repo,
            audit_repo,
            pubsub,
            mock_zap,
            jwt_secret,
        };

        app.seed_default_users().await;
        app
    }

    pub async fn seed_default_users(&self) {
        self.seed_user_with_password("admin@kds.local", "AdminSecret123!", UserRole::Admin)
            .await;
        self.seed_user_with_password(
            "seceng@kds.local",
            "SecEngSecret123!",
            UserRole::SecurityEngineer,
        )
        .await;
        self.seed_user_with_password("dev@kds.local", "DevSecret123!", UserRole::Developer)
            .await;
        self.seed_user_with_password("auditor@kds.local", "AuditorSecret123!", UserRole::Auditor)
            .await;
    }

    pub async fn seed_user_with_password(
        &self,
        email: &str,
        password: &str,
        role: UserRole,
    ) -> (Uuid, String) {
        let user_id = Uuid::new_v4();
        let pass_hash = hash_password(password);
        self.user_repo
            .insert_user(user_id, email, "Test User", &pass_hash, role, true)
            .await;
        let token = create_jwt_token(user_id, email, role, &self.jwt_secret, 15);
        (user_id, token)
    }

    pub async fn seed_admin(&self) -> (Uuid, String) {
        self.seed_user_with_password("admin@kds.local", "AdminSecret123!", UserRole::Admin)
            .await
    }

    pub async fn seed_sec_eng(&self) -> (Uuid, String) {
        self.seed_user_with_password(
            "seceng@kds.local",
            "SecEngSecret123!",
            UserRole::SecurityEngineer,
        )
        .await
    }

    pub async fn seed_developer(&self) -> (Uuid, String) {
        self.seed_user_with_password("dev@kds.local", "DevSecret123!", UserRole::Developer)
            .await
    }

    pub async fn seed_auditor(&self) -> (Uuid, String) {
        self.seed_user_with_password("auditor@kds.local", "AuditorSecret123!", UserRole::Auditor)
            .await
    }

    pub async fn create_api_key(&self, user_id: Uuid, name: &str) -> String {
        let raw_key = format!("appsec_live_{}", Uuid::new_v4().simple());
        let prefix = if raw_key.len() >= 12 {
            &raw_key[..12]
        } else {
            &raw_key
        };
        let key_hash = hash_api_key(&raw_key);
        self.user_repo
            .insert_api_key(Uuid::new_v4(), user_id, name, prefix, &key_hash, None)
            .await;
        raw_key
    }

    pub fn expired_token(&self, role: UserRole) -> String {
        create_expired_jwt_token(Uuid::new_v4(), "expired@kds.local", role, &self.jwt_secret)
    }

    pub fn tampered_token(&self, role: UserRole) -> String {
        create_tampered_jwt_token(Uuid::new_v4(), "tampered@kds.local", role)
    }

    pub async fn seed_application(
        &self,
        name: &str,
        base_url: &str,
        is_authorized: bool,
    ) -> ApplicationResponse {
        let app_id = Uuid::new_v4();
        let app = ApplicationResponse {
            id: app_id,
            name: name.to_string(),
            description: Some("Test application description".to_string()),
            base_url: base_url.to_string(),
            environment: AppEnvironment::Staging,
            criticality: AppCriticality::High,
            owner_id: None,
            team_name: Some("SecOps".to_string()),
            include_regexes: vec![format!("{}.*", base_url)],
            exclude_regexes: vec!["/logout.*".to_string()],
            has_auth_configured: false,
            cron_schedule: None,
            is_authorized,
            latest_risk_score: 0.0,
            last_scanned_at: None,
            open_counts: SeverityCounts::default(),
            created_at: Utc::now(),
        };
        self.app_repo.insert_app(app.clone()).await;
        app
    }

    pub async fn run_mock_scan(&self, scan_id: Uuid, app_id: Uuid, alerts: Vec<ZapRawAlert>) {
        self.scan_repo
            .update_status(scan_id, ScanStatus::Spidering, 30, None)
            .await;
        self.scan_repo
            .update_status(scan_id, ScanStatus::ActiveScanning, 60, None)
            .await;
        self.scan_repo
            .update_status(scan_id, ScanStatus::Ingesting, 90, None)
            .await;

        let mut counts = SeverityCounts::default();
        for alert in &alerts {
            match alert.risk.to_lowercase().as_str() {
                "high" => counts.high += 1,
                "medium" => counts.medium += 1,
                "low" => counts.low += 1,
                _ => counts.info += 1,
            }
        }

        let diff = ScanDiffSummary {
            previous_scan_id: None,
            new_count: alerts.len() as i32,
            persistent_count: 0,
            fixed_count: 0,
            regressed_count: 0,
            risk_score_delta: 25.0,
        };

        self.scan_repo.complete_scan(scan_id, counts, diff, 25.0).await;
        self.app_repo.update_risk_posture(app_id, 25.0).await;
    }

    pub async fn seed_scan_with_findings(
        &self,
        app_id: Uuid,
        findings: Vec<serde_json::Value>,
    ) -> ScanResponse {
        let scan_id = Uuid::new_v4();
        let mut counts = SeverityCounts::default();
        for f in &findings {
            let sev = f.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
            match sev.to_lowercase().as_str() {
                "critical" => counts.critical += 1,
                "high" => counts.high += 1,
                "medium" => counts.medium += 1,
                "low" => counts.low += 1,
                _ => counts.info += 1,
            }
        }
        let diff = ScanDiffSummary {
            previous_scan_id: None,
            new_count: findings.len() as i32,
            persistent_count: 0,
            fixed_count: 0,
            regressed_count: 0,
            risk_score_delta: 10.0,
        };
        let scan = ScanResponse {
            id: scan_id,
            application_id: app_id,
            scan_type: ScanType::FullActive,
            status: ScanStatus::Completed,
            progress_percent: 100,
            severity_counts: counts,
            diff_summary: diff,
            overall_risk_score: 10.0,
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            duration_seconds: Some(60),
            error_message: None,
        };
        self.scan_repo.insert_scan(scan.clone()).await;
        self.scan_repo.insert_findings(scan_id, findings).await;
        scan
    }
}

// -----------------------------------------------------------------------------
// Authentication & RBAC Helper Functions
// -----------------------------------------------------------------------------

pub enum AuthIdentity {
    User(UserRecord),
    ApiKey(UserRecord, ApiKeyRecord),
}

impl AuthIdentity {
    pub fn user(&self) -> &UserRecord {
        match self {
            Self::User(u) => u,
            Self::ApiKey(u, _) => u,
        }
    }
}

pub async fn extract_identity(
    state: &SharedAppState,
    headers: &HeaderMap,
) -> Result<AuthIdentity, (StatusCode, &'static str, &'static str)> {
    // 1. Check Authorization Bearer header
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        let h_str = auth_header
            .to_str()
            .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Malformed Authorization header"))?;
        let token = h_str
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Missing Bearer prefix"))?;
        if token.trim().is_empty() {
            return Err((StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Empty Bearer token"));
        }
        let claims = decode_jwt_token(token, &state.jwt_secret)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Token validation failed"))?;
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid subject claim"))?;
        let user = state
            .user_repo
            .find_by_id(user_id)
            .await
            .ok_or((StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "User not found"))?;
        if !user.is_active {
            return Err((StatusCode::UNAUTHORIZED, "USER_INACTIVE", "User account is deactivated"));
        }
        return Ok(AuthIdentity::User(user));
    }

    // 2. Check X-API-Key header (case-insensitive in HeaderMap)
    if let Some(api_key_header) = headers.get("x-api-key") {
        let key_str = api_key_header
            .to_str()
            .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_API_KEY", "Malformed API key header"))?;
        if key_str.is_empty() || !key_str.starts_with("appsec_live_") {
            return Err((StatusCode::UNAUTHORIZED, "INVALID_API_KEY", "Invalid API key format"));
        }
        let key_hash = hash_api_key(key_str);
        let key_rec = state
            .user_repo
            .find_api_key_by_hash(&key_hash)
            .await
            .ok_or((StatusCode::UNAUTHORIZED, "INVALID_API_KEY", "API key not found or revoked"))?;
        if let Some(exp) = key_rec.expires_at {
            if Utc::now() > exp {
                return Err((StatusCode::UNAUTHORIZED, "API_KEY_EXPIRED", "API key has expired"));
            }
        }
        state.user_repo.update_api_key_last_used(&key_hash).await;
        let user = state
            .user_repo
            .find_by_id(key_rec.user_id)
            .await
            .ok_or((StatusCode::UNAUTHORIZED, "INVALID_API_KEY", "Key owner not found"))?;
        if !user.is_active {
            return Err((StatusCode::UNAUTHORIZED, "USER_INACTIVE", "User account is deactivated"));
        }
        return Ok(AuthIdentity::ApiKey(user, key_rec));
    }

    Err((
        StatusCode::UNAUTHORIZED,
        "INVALID_TOKEN",
        "Missing Authorization or X-API-Key header",
    ))
}

pub fn check_rbac(
    identity: &AuthIdentity,
    allowed_roles: &[UserRole],
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let user = identity.user();
    if !allowed_roles.contains(&user.role) {
        return Err((
            StatusCode::FORBIDDEN,
            "FORBIDDEN_RESOURCE",
            "Insufficient role privileges",
        ));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// In-Memory Axum HTTP Router & Route Handlers
// -----------------------------------------------------------------------------

fn build_router(state: SharedAppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/api/v1/healthz", get(healthz_handler))
        // Auth routes
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/refresh", post(refresh_handler))
        .route("/api/v1/auth/logout", post(logout_handler))
        .route("/api/v1/auth/me", get(me_handler))
        .route(
            "/api/v1/auth/api-keys",
            get(list_api_keys_handler).post(create_api_key_handler),
        )
        .route(
            "/api/v1/auth/api-keys/:key_id",
            delete(delete_api_key_handler),
        )
        // App routes
        .route("/api/v1/apps", get(list_apps_handler).post(create_app_handler))
        .route(
            "/api/v1/apps/:app_id",
            get(get_app_handler)
                .patch(patch_app_handler)
                .delete(delete_app_handler),
        )
        .route("/api/v1/apps/:app_id/auth", put(configure_app_auth_handler))
        .route("/api/v1/apps/:app_id/trends", get(get_app_trends_handler))
        // Scan REST routes
        .route(
            "/api/v1/apps/:app_id/scans",
            get(list_scans_for_app_handler).post(trigger_scan_handler),
        )
        .route("/api/v1/scans/compare", get(compare_scans_handler))
        .route("/api/v1/scans/:scan_id", get(get_scan_handler))
        .route("/api/v1/scans/:scan_id/cancel", post(cancel_scan_handler))
        .route("/api/v1/scans/:scan_id/findings", get(get_scan_findings_handler))
        // WebSocket routes
        .route("/ws/v1/scans/:scan_id", get(ws_scan_progress_handler))
        .route("/ws/v1/notifications", get(ws_notifications_handler))
        .with_state(state)
}

pub fn error_json(status: StatusCode, code: &str, message: &str) -> Response {
    let req_id = format!("req_{}", Uuid::new_v4().simple());
    let env = ErrorEnvelope {
        error: ErrorDetail {
            code: code.to_string(),
            message: message.to_string(),
            request_id: req_id,
        },
    };
    (status, Json(env)).into_response()
}

async fn healthz_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

async fn login_handler(
    State(state): State<SharedAppState>,
    body_bytes: axum::body::Bytes,
) -> Response {
    let payload: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid JSON payload"),
    };
    let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let password = payload.get("password").and_then(|v| v.as_str()).unwrap_or("");

    if email.trim().is_empty() || password.is_empty() {
        return error_json(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Email and password must not be empty",
        );
    }

    let user_opt = state.user_repo.find_by_email(email).await;
    match user_opt {
        Some(user) => {
            let hashed_attempt = hash_password(password);
            if user.password_hash == hashed_attempt {
                if !user.is_active {
                    return error_json(
                        StatusCode::UNAUTHORIZED,
                        "USER_INACTIVE",
                        "User account is deactivated",
                    );
                }
                state.user_repo.update_last_login(user.id).await;
                let mut updated_user = user.clone();
                updated_user.last_login_at = Some(Utc::now());

                let token = create_jwt_token(
                    user.id,
                    &user.email,
                    user.role,
                    &state.jwt_secret,
                    15,
                );
                let refresh_token = format!("refresh_{}_{}", user.id.simple(), Uuid::new_v4().simple());
                state.user_repo.store_refresh_token(user.id, &refresh_token, 7).await;

                let resp = TokenResponse {
                    access_token: token,
                    refresh_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 900,
                    user: updated_user.to_profile(),
                };
                (StatusCode::OK, Json(resp)).into_response()
            } else {
                error_json(
                    StatusCode::UNAUTHORIZED,
                    "INVALID_CREDENTIALS",
                    "Invalid email or password",
                )
            }
        }
        None => error_json(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "Invalid email or password",
        ),
    }
}

async fn refresh_handler(
    State(state): State<SharedAppState>,
    body_bytes: axum::body::Bytes,
) -> Response {
    let payload: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid JSON payload"),
    };
    let rt = payload.get("refresh_token").and_then(|v| v.as_str()).unwrap_or("");
    if rt.trim().is_empty() || !rt.starts_with("refresh_") {
        return error_json(
            StatusCode::UNAUTHORIZED,
            "INVALID_REFRESH_TOKEN",
            "Invalid refresh token signature or format",
        );
    }

    let new_rt = format!("refresh_{}_{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let user_id = match state.user_repo.rotate_refresh_token(rt, &new_rt, 7).await {
        Ok(uid) => uid,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };

    let user = match state.user_repo.find_by_id(user_id).await {
        Some(u) => u,
        None => return error_json(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "User not found"),
    };
    if !user.is_active {
        return error_json(StatusCode::UNAUTHORIZED, "USER_INACTIVE", "User account is deactivated");
    }

    let new_access_token = create_jwt_token(
        user.id,
        &user.email,
        user.role,
        &state.jwt_secret,
        15,
    );

    let resp = TokenResponse {
        access_token: new_access_token,
        refresh_token: new_rt,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        user: user.to_profile(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

async fn logout_handler(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };

    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        if let Some(rt) = v.get("refresh_token").and_then(|r| r.as_str()) {
            state.user_repo.revoke_refresh_token(rt).await;
        } else {
            state.user_repo.revoke_all_refresh_tokens_for_user(identity.user().id).await;
        }
    } else {
        state.user_repo.revoke_all_refresh_tokens_for_user(identity.user().id).await;
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "logged_out"}))).into_response()
}

async fn me_handler(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    (StatusCode::OK, Json(identity.user())).into_response()
}

async fn list_api_keys_handler(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin, UserRole::SecurityEngineer]) {
        return error_json(status, code, msg);
    }
    let keys = state.user_repo.list_api_keys_for_user(identity.user().id).await;
    let resp: Vec<ApiKeyResponse> = keys.into_iter().map(|k| k.to_response()).collect();
    (StatusCode::OK, Json(resp)).into_response()
}

async fn create_api_key_handler(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin, UserRole::SecurityEngineer]) {
        return error_json(status, code, msg);
    }
    let payload: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "INVALID_PAYLOAD", "Malformed JSON"),
    };
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.trim().is_empty() || name.len() > 100 {
        return error_json(
            StatusCode::BAD_REQUEST,
            "INVALID_API_KEY_NAME",
            "API key name must be between 1 and 100 characters",
        );
    }
    let expires_at = if let Some(exp_val) = payload.get("expires_at") {
        if !exp_val.is_null() {
            match serde_json::from_value::<DateTime<Utc>>(exp_val.clone()) {
                Ok(exp) => {
                    if exp <= Utc::now() {
                        return error_json(
                            StatusCode::BAD_REQUEST,
                            "INVALID_EXPIRATION",
                            "API key expiration must be in the future",
                        );
                    }
                    Some(exp)
                }
                Err(_) => {
                    return error_json(
                        StatusCode::BAD_REQUEST,
                        "INVALID_EXPIRATION",
                        "Invalid expiration timestamp format",
                    )
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let raw_secret = format!(
        "appsec_live_{}_{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let prefix = raw_secret[..12].to_string();
    let hash = hash_api_key(&raw_secret);
    let key_id = Uuid::new_v4();

    state
        .user_repo
        .insert_api_key(
            key_id,
            identity.user().id,
            name,
            &prefix,
            &hash,
            expires_at,
        )
        .await;

    let resp = CreateApiKeyResponse {
        id: key_id,
        name: name.to_string(),
        key_prefix: prefix,
        secret_key: raw_secret,
        expires_at,
        created_at: Utc::now(),
    };
    (StatusCode::CREATED, Json(resp)).into_response()
}

async fn delete_api_key_handler(
    State(state): State<SharedAppState>,
    AxumPath(key_id_str): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin, UserRole::SecurityEngineer]) {
        return error_json(status, code, msg);
    }
    let key_id = match Uuid::parse_str(&key_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "API_KEY_NOT_FOUND", "Invalid key UUID"),
    };
    if state.user_repo.delete_api_key(key_id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        error_json(StatusCode::NOT_FOUND, "API_KEY_NOT_FOUND", "API key not found")
    }
}

async fn list_apps_handler(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err((status, code, msg)) = extract_identity(&state, &headers).await {
        return error_json(status, code, msg);
    }
    let mut apps = state.app_repo.list_apps().await;
    if let Some(env_filter) = params.get("environment") {
        let env_clean = env_filter.trim().to_lowercase();
        apps.retain(|a| a.environment.as_str() == env_clean);
    }
    (StatusCode::OK, Json(apps)).into_response()
}

async fn create_app_handler(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin, UserRole::SecurityEngineer]) {
        return error_json(status, code, msg);
    }

    let payload_val: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "INVALID_PAYLOAD", "Malformed JSON body"),
    };

    // Check authorization flag
    let is_auth = payload_val
        .get("is_authorized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_auth {
        return error_json(
            StatusCode::BAD_REQUEST,
            "UNAUTHORIZED_TARGET",
            "Explicit authorization flag must be verified before scanning",
        );
    }

    let name = payload_val.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.trim().is_empty() || name.len() > 150 {
        return error_json(
            StatusCode::BAD_REQUEST,
            "INVALID_APPLICATION_NAME",
            "Application name must be between 1 and 150 characters",
        );
    }

    let base_url = payload_val.get("base_url").and_then(|v| v.as_str()).unwrap_or("");
    if (!base_url.starts_with("http://") && !base_url.starts_with("https://"))
        || base_url.starts_with("ftp://")
    {
        return error_json(
            StatusCode::BAD_REQUEST,
            "INVALID_APPLICATION_URL",
            "Application URL must start with http:// or https://",
        );
    }

    // Check port if specified
    if let Some(pos) = base_url.rfind(':') {
        let remainder = &base_url[pos + 1..];
        let port_str: String = remainder.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !port_str.is_empty() {
            if let Ok(port) = port_str.parse::<u64>() {
                if port > 65535 {
                    return error_json(
                        StatusCode::BAD_REQUEST,
                        "INVALID_APPLICATION_URL",
                        "Port out of valid range (1-65535)",
                    );
                }
            }
        }
    }

    if let Some(desc) = payload_val.get("description").and_then(|v| v.as_str()) {
        if desc.len() > 4096 {
            return error_json(
                StatusCode::BAD_REQUEST,
                "INVALID_PAYLOAD",
                "Description exceeds maximum 4096 characters",
            );
        }
    }

    let cron_schedule = payload_val.get("cron_schedule").and_then(|v| v.as_str());
    if let Some(cron) = cron_schedule {
        if cron.split_whitespace().count() != 5 {
            return error_json(
                StatusCode::BAD_REQUEST,
                "INVALID_CRON_SCHEDULE",
                "Cron schedule must follow standard 5-part format",
            );
        }
    }

    let req: CreateApplicationRequest = match serde_json::from_value(payload_val) {
        Ok(r) => r,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "INVALID_PAYLOAD", "Deserialization failed"),
    };

    if state
        .app_repo
        .find_by_name_and_env(&req.name, req.environment)
        .await
        .is_some()
    {
        return error_json(
            StatusCode::CONFLICT,
            "DUPLICATE_APPLICATION",
            "An application with this name already exists in this environment",
        );
    }

    let app = ApplicationResponse {
        id: Uuid::new_v4(),
        name: req.name,
        description: req.description,
        base_url: req.base_url,
        environment: req.environment,
        criticality: req.criticality,
        owner_id: Some(identity.user().id),
        team_name: req.team_name,
        include_regexes: req.include_regexes,
        exclude_regexes: req.exclude_regexes,
        has_auth_configured: false,
        cron_schedule: req.cron_schedule,
        is_authorized: req.is_authorized,
        latest_risk_score: 0.0,
        last_scanned_at: None,
        open_counts: SeverityCounts::default(),
        created_at: Utc::now(),
    };
    state.app_repo.insert_app(app.clone()).await;
    (StatusCode::CREATED, Json(app)).into_response()
}

async fn get_app_handler(
    State(state): State<SharedAppState>,
    AxumPath(app_id_str): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err((status, code, msg)) = extract_identity(&state, &headers).await {
        return error_json(status, code, msg);
    }
    let app_id = match Uuid::parse_str(&app_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    };
    match state.app_repo.find_by_id(app_id).await {
        Some(app) => (StatusCode::OK, Json(app)).into_response(),
        None => error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    }
}

async fn patch_app_handler(
    State(state): State<SharedAppState>,
    AxumPath(app_id_str): AxumPath<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin, UserRole::SecurityEngineer]) {
        return error_json(status, code, msg);
    }
    let app_id = match Uuid::parse_str(&app_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    };
    if state.app_repo.find_by_id(app_id).await.is_none() {
        return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found");
    }
    let req: UpdateApplicationRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "INVALID_PAYLOAD", "Malformed update payload"),
    };
    match state.app_repo.update_app(app_id, req).await {
        Some(app) => (StatusCode::OK, Json(app)).into_response(),
        None => error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    }
}

async fn delete_app_handler(
    State(state): State<SharedAppState>,
    AxumPath(app_id_str): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin]) {
        return error_json(status, code, msg);
    }
    let app_id = match Uuid::parse_str(&app_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    };
    if state.app_repo.delete_app(app_id).await {
        (StatusCode::OK, Json(serde_json::json!({"status": "deleted", "id": app_id}))).into_response()
    } else {
        error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found")
    }
}

async fn configure_app_auth_handler(
    State(state): State<SharedAppState>,
    AxumPath(app_id_str): AxumPath<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin, UserRole::SecurityEngineer]) {
        return error_json(status, code, msg);
    }
    let app_id = match Uuid::parse_str(&app_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    };
    if state.app_repo.find_by_id(app_id).await.is_none() {
        return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found");
    }

    let payload: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "INVALID_PAYLOAD", "Malformed JSON payload"),
    };

    let auth_type = payload.get("auth_type").and_then(|v| v.as_str()).unwrap_or("");
    let valid_types = ["bearer_token", "cookie", "header", "basic"];
    if !valid_types.contains(&auth_type) {
        return error_json(
            StatusCode::BAD_REQUEST,
            "INVALID_AUTH_TYPE",
            "Unsupported application auth configuration type",
        );
    }

    let auth_data = match payload.get("auth_data") {
        Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v.clone(),
        _ => {
            return error_json(
                StatusCode::BAD_REQUEST,
                "INVALID_AUTH_DATA",
                "Auth data cannot be empty",
            )
        }
    };

    state.app_repo.set_auth_configured(app_id, true, Some(auth_data)).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "configured", "has_auth_configured": true})),
    )
        .into_response()
}

async fn get_app_trends_handler(
    State(state): State<SharedAppState>,
    AxumPath(app_id_str): AxumPath<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err((status, code, msg)) = extract_identity(&state, &headers).await {
        return error_json(status, code, msg);
    }
    let app_id = match Uuid::parse_str(&app_id_str) {
        Ok(id) => id,
        Err(_) => {
            return error_json(
                StatusCode::BAD_REQUEST,
                "INVALID_UUID",
                "Malformed application UUID in path",
            )
        }
    };

    let days = if let Some(days_str) = params.get("days") {
        match days_str.parse::<i64>() {
            Ok(d) if d >= 0 => Some(d),
            _ => {
                return error_json(
                    StatusCode::BAD_REQUEST,
                    "INVALID_QUERY_PARAMETER",
                    "The days parameter must be a non-negative integer",
                )
            }
        }
    } else {
        None
    };

    match state.app_repo.get_trends(app_id, &state.scan_repo, days).await {
        Some(trends) => (StatusCode::OK, Json(trends)).into_response(),
        None => error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    }
}

async fn trigger_scan_handler(
    State(state): State<SharedAppState>,
    AxumPath(app_id_str): AxumPath<String>,
    headers: HeaderMap,
    Json(payload): Json<TriggerScanRequest>,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin, UserRole::SecurityEngineer]) {
        return error_json(status, code, msg);
    }
    let app_id = match Uuid::parse_str(&app_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    };
    let app_opt = state.app_repo.find_by_id(app_id).await;
    let app = match app_opt {
        Some(a) => a,
        None => {
            return error_json(
                StatusCode::NOT_FOUND,
                "APPLICATION_NOT_FOUND",
                "Application not found",
            );
        }
    };

    if !app.is_authorized {
        return error_json(
            StatusCode::BAD_REQUEST,
            "UNAUTHORIZED_TARGET",
            "Target application is not authorized for scanning",
        );
    }

    if state.scan_repo.has_active_scan(app_id).await {
        return error_json(
            StatusCode::BAD_REQUEST,
            "SCAN_ALREADY_IN_PROGRESS",
            "A scan is already in progress for this application",
        );
    }

    let scan = ScanResponse {
        id: Uuid::new_v4(),
        application_id: app_id,
        scan_type: payload.scan_type,
        status: ScanStatus::Queued,
        progress_percent: 0,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: None,
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    };
    state.scan_repo.insert_scan(scan.clone()).await;
    (StatusCode::ACCEPTED, Json(scan)).into_response()
}

async fn list_scans_for_app_handler(
    State(state): State<SharedAppState>,
    AxumPath(app_id_str): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err((status, code, msg)) = extract_identity(&state, &headers).await {
        return error_json(status, code, msg);
    }
    let app_id = match Uuid::parse_str(&app_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found"),
    };
    if state.app_repo.find_by_id(app_id).await.is_none() {
        return error_json(StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND", "Application not found");
    }
    let scans = state.scan_repo.list_scans_for_app(app_id).await;
    (StatusCode::OK, Json(scans)).into_response()
}

async fn cancel_scan_handler(
    State(state): State<SharedAppState>,
    AxumPath(scan_id_str): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let identity = match extract_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, code, msg)) => return error_json(status, code, msg),
    };
    if let Err((status, code, msg)) = check_rbac(&identity, &[UserRole::Admin, UserRole::SecurityEngineer]) {
        return error_json(status, code, msg);
    }
    let scan_id = match Uuid::parse_str(&scan_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Scan not found"),
    };
    match state.scan_repo.cancel_scan(scan_id).await {
        Ok(scan) => (StatusCode::OK, Json(scan)).into_response(),
        Err("SCAN_NOT_FOUND") => error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Scan not found"),
        Err("SCAN_CANNOT_BE_CANCELLED") => error_json(
            StatusCode::BAD_REQUEST,
            "SCAN_CANNOT_BE_CANCELLED",
            "Scan cannot be cancelled in its current state",
        ),
        Err(_) => error_json(StatusCode::BAD_REQUEST, "SCAN_ERROR", "Failed to cancel scan"),
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct FindingsQuery {
    pub severity: Option<String>,
}

async fn get_scan_findings_handler(
    State(state): State<SharedAppState>,
    AxumPath(scan_id_str): AxumPath<String>,
    headers: HeaderMap,
    Query(params): Query<FindingsQuery>,
) -> Response {
    if let Err((status, code, msg)) = extract_identity(&state, &headers).await {
        return error_json(status, code, msg);
    }
    let scan_id = match Uuid::parse_str(&scan_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Scan not found"),
    };
    if state.scan_repo.get_scan(scan_id).await.is_none() {
        return error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Scan not found");
    }
    let mut findings = state
        .scan_repo
        .get_findings(scan_id)
        .await
        .unwrap_or_default();

    if let Some(sev) = params.severity {
        let sev_lower = sev.to_lowercase();
        findings.retain(|f| {
            if let Some(s) = f.get("severity").and_then(|v| v.as_str()) {
                s.to_lowercase() == sev_lower
            } else {
                false
            }
        });
    }

    (StatusCode::OK, Json(findings)).into_response()
}

async fn compare_scans_handler(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err((status, code, msg)) = extract_identity(&state, &headers).await {
        return error_json(status, code, msg);
    }
    let base_str = match params.get("base") {
        Some(s) if !s.trim().is_empty() => s,
        _ => return error_json(StatusCode::BAD_REQUEST, "INVALID_INPUT", "Missing base scan ID parameter"),
    };
    let target_str = match params.get("target") {
        Some(s) if !s.trim().is_empty() => s,
        _ => return error_json(StatusCode::BAD_REQUEST, "INVALID_INPUT", "Missing target scan ID parameter"),
    };

    let base_id = match Uuid::parse_str(base_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "INVALID_INPUT", "Malformed base scan UUID"),
    };
    let target_id = match Uuid::parse_str(target_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "INVALID_INPUT", "Malformed target scan UUID"),
    };

    let base_scan = match state.scan_repo.get_scan(base_id).await {
        Some(s) => s,
        None => return error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Base scan not found"),
    };
    let target_scan = match state.scan_repo.get_scan(target_id).await {
        Some(s) => s,
        None => return error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Target scan not found"),
    };

    if base_scan.application_id != target_scan.application_id {
        return error_json(
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
            "Cannot compare scans belonging to different applications",
        );
    }

    let diff_summary = if base_id == target_id {
        ScanDiffSummary::default()
    } else {
        let base_findings = state.scan_repo.get_findings(base_id).await.unwrap_or_default();
        let target_findings = state.scan_repo.get_findings(target_id).await.unwrap_or_default();
        if !base_findings.is_empty() || !target_findings.is_empty() {
            fn extract_fps(vals: &[serde_json::Value]) -> Vec<FindingFingerprint> {
                vals.iter().filter_map(|v| {
                    let fp = v.get("fingerprint").and_then(|f| f.as_str())?.to_string();
                    let cvss = v.get("cvss_score").and_then(|s| s.as_f64()).unwrap_or(5.0);
                    let triage_str = v.get("triage_status").or_else(|| v.get("status")).and_then(|s| s.as_str()).unwrap_or("open");
                    let triage: RemediationStatus = serde_json::from_value(serde_json::json!(triage_str)).unwrap_or(RemediationStatus::Open);
                    Some(FindingFingerprint::new(fp).with_status(triage).with_cvss(cvss))
                }).collect()
            }
            let base_fps = extract_fps(&base_findings);
            let target_fps = extract_fps(&target_findings);
            let diff_res = diff_scans(&base_fps, &target_fps);
            diff_res.summary
        } else {
            target_scan.diff_summary.clone()
        }
    };

    let comparison = ScanComparisonResponse {
        base_scan_id: base_id,
        target_scan_id: target_id,
        diff_summary,
    };
    (StatusCode::OK, Json(comparison)).into_response()
}

async fn ws_scan_progress_handler(
    State(state): State<SharedAppState>,
    AxumPath(scan_id_str): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
    ws: Option<WebSocketUpgrade>,
) -> Response {
    let token = match params.get("token") {
        Some(t) if !t.trim().is_empty() => t,
        _ => {
            return error_json(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Missing authentication token",
            )
        }
    };
    let claims = match decode_jwt_token(token, &state.jwt_secret) {
        Ok(c) => c,
        Err(_) => {
            return error_json(
                StatusCode::UNAUTHORIZED,
                "INVALID_TOKEN",
                "Token validation failed",
            )
        }
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid subject"),
    };
    let user = match state.user_repo.find_by_id(user_id).await {
        Some(u) => u,
        None => return error_json(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "User not found"),
    };
    if !user.is_active {
        return error_json(StatusCode::UNAUTHORIZED, "USER_INACTIVE", "User account is deactivated");
    }

    let scan_id = match Uuid::parse_str(&scan_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Scan not found"),
    };
    if state.scan_repo.get_scan(scan_id).await.is_none() {
        return error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Scan not found");
    }

    if let Some(upgrade) = ws {
        upgrade.on_upgrade(|mut socket| async move {
            let _ = socket.send(axum::extract::ws::Message::Ping(vec![])).await;
        })
    } else {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ws_handshake_accepted",
                "scan_id": scan_id
            })),
        )
            .into_response()
    }
}

async fn ws_notifications_handler(
    State(state): State<SharedAppState>,
    Query(params): Query<HashMap<String, String>>,
    ws: Option<WebSocketUpgrade>,
) -> Response {
    let token = match params.get("token") {
        Some(t) if !t.trim().is_empty() => t,
        _ => {
            return error_json(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Missing authentication token",
            )
        }
    };
    let claims = match decode_jwt_token(token, &state.jwt_secret) {
        Ok(c) => c,
        Err(_) => {
            return error_json(
                StatusCode::UNAUTHORIZED,
                "INVALID_TOKEN",
                "Token validation failed",
            )
        }
    };
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid subject"),
    };
    let user = match state.user_repo.find_by_id(user_id).await {
        Some(u) => u,
        None => return error_json(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "User not found"),
    };
    if !user.is_active {
        return error_json(StatusCode::UNAUTHORIZED, "USER_INACTIVE", "User account is deactivated");
    }

    if let Some(upgrade) = ws {
        upgrade.on_upgrade(|mut socket| async move {
            let _ = socket.send(axum::extract::ws::Message::Ping(vec![])).await;
        })
    } else {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ws_notifications_accepted"
            })),
        )
            .into_response()
    }
}

async fn get_scan_handler(
    State(state): State<SharedAppState>,
    AxumPath(scan_id_str): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err((status, code, msg)) = extract_identity(&state, &headers).await {
        return error_json(status, code, msg);
    }
    let scan_id = match Uuid::parse_str(&scan_id_str) {
        Ok(id) => id,
        Err(_) => return error_json(StatusCode::NOT_FOUND, "SCAN_NOT_FOUND", "Scan not found"),
    };
    let scan_opt = state.scan_repo.get_scan(scan_id).await;
    match scan_opt {
        Some(scan) => (StatusCode::OK, Json(scan)).into_response(),
        None => error_json(
            StatusCode::NOT_FOUND,
            "SCAN_NOT_FOUND",
            "Scan not found",
        ),
    }
}

// -----------------------------------------------------------------------------
// Integrated Test Harness with Real api-server and scan-worker
// -----------------------------------------------------------------------------

pub struct IntegratedHarness {
    pub client: TestClient,
    pub api_state: api_server::AppState,
    pub scan_engine: Arc<scan_worker::ScanWorkerEngine>,
    pub app_repo: Arc<infra::memory::InMemoryAppRepo>,
    pub scan_repo: Arc<infra::memory::InMemoryScanRepo>,
    pub vuln_repo: Arc<infra::memory::InMemoryVulnRepo>,
    pub user_repo: Arc<infra::memory::InMemoryUserRepo>,
    pub audit_repo: Arc<infra::memory::InMemoryAuditLogRepo>,
    pub pubsub: Arc<infra::memory::InMemoryPubSub>,
    pub mock_zap: Arc<infra::zap::MockZapClient>,
    pub pdf_generator: Arc<infra::pdf::SimplePdfGenerator>,
    pub jwt_secret: String,
}

impl IntegratedHarness {
    pub async fn new() -> Self {
        let jwt_secret = "test_jwt_secret_key_appsec_platform_2026_super_secure".to_string();
        let app_repo = Arc::new(infra::memory::InMemoryAppRepo::new());
        let scan_repo = Arc::new(infra::memory::InMemoryScanRepo::new());
        let vuln_repo = Arc::new(infra::memory::InMemoryVulnRepo::new());
        let user_repo = Arc::new(infra::memory::InMemoryUserRepo::new());
        let audit_repo = Arc::new(infra::memory::InMemoryAuditLogRepo::new());
        let pubsub = Arc::new(infra::memory::InMemoryPubSub::new());
        let mock_zap = Arc::new(infra::zap::MockZapClient::new());
        let pdf_generator = Arc::new(infra::pdf::SimplePdfGenerator::new());

        let api_state = api_server::AppState::new(
            app_repo.clone(),
            scan_repo.clone(),
            vuln_repo.clone(),
            user_repo.clone(),
            audit_repo.clone(),
            pubsub.clone(),
            pdf_generator.clone(),
            mock_zap.clone(),
            jwt_secret.clone(),
        );
        api_state.seed_default_users().await;

        let router = api_server::create_router(api_state.clone());
        let client = TestClient::new(router);

        let scan_engine = Arc::new(scan_worker::ScanWorkerEngine::new(
            app_repo.clone(),
            scan_repo.clone(),
            vuln_repo.clone(),
            mock_zap.clone(),
            pubsub.clone(),
        ));

        Self {
            client,
            api_state,
            scan_engine,
            app_repo,
            scan_repo,
            vuln_repo,
            user_repo,
            audit_repo,
            pubsub,
            mock_zap,
            pdf_generator,
            jwt_secret,
        }
    }

    pub async fn token_for_email(&self, email: &str) -> String {
        use infra::traits::UserRepository;
        let user = self
            .user_repo
            .find_by_email(email)
            .await
            .unwrap()
            .expect("User must exist");
        api_server::create_jwt_token(user.id, &user.email, user.role, &self.jwt_secret, 15)
    }

    pub async fn admin_token(&self) -> String {
        self.token_for_email("admin@kds.local").await
    }

    pub async fn seceng_token(&self) -> String {
        self.token_for_email("seceng@kds.local").await
    }

    pub async fn dev_token(&self) -> String {
        self.token_for_email("dev@kds.local").await
    }

    pub async fn auditor_token(&self) -> String {
        self.token_for_email("auditor@kds.local").await
    }

    pub async fn create_api_key(&self, user_id: Uuid, name: &str) -> String {
        use infra::traits::UserRepository;
        use shared_types::auth::CreateApiKeyRequest;
        let raw_key = format!("appsec_live_{}", Uuid::new_v4().simple());
        let prefix = &raw_key[..12];
        let hash = api_server::hash_api_key(&raw_key);
        let req = CreateApiKeyRequest {
            name: name.to_string(),
            expires_at: None,
        };
        self.user_repo
            .create_api_key(user_id, &req, prefix, &hash)
            .await
            .unwrap();
        raw_key
    }

    pub async fn seed_application(
        &self,
        name: &str,
        base_url: &str,
        is_authorized: bool,
    ) -> ApplicationResponse {
        use infra::traits::AppRepository;
        use shared_types::app::CreateApplicationRequest;
        let req = CreateApplicationRequest {
            name: name.to_string(),
            description: Some("Integrated App Description".to_string()),
            base_url: base_url.to_string(),
            environment: AppEnvironment::Staging,
            criticality: AppCriticality::High,
            team_name: Some("SecOps".to_string()),
            include_regexes: vec![format!("{}.*", base_url)],
            exclude_regexes: vec!["/logout.*".to_string()],
            cron_schedule: None,
            is_authorized,
        };
        self.app_repo.create(&req, None).await.unwrap()
    }

    pub async fn seed_vulnerability(
        &self,
        app_id: Uuid,
        scan_id: Uuid,
        title: &str,
        severity: SeverityLevel,
        cwe_id: Option<i32>,
    ) -> VulnerabilityDetail {
        use infra::traits::{FindingIngestionInput, VulnRepository};
        let input = FindingIngestionInput {
            zap_plugin_id: "40018".to_string(),
            title: title.to_string(),
            cwe_id,
            wasc_id: Some(19),
            confidence: "High".to_string(),
            http_method: "GET".to_string(),
            affected_url: format!("https://example.com/api/test/{}", Uuid::new_v4().simple()),
            affected_param: Some("id".to_string()),
            attack_payload: Some("' OR '1'='1".to_string()),
            evidence_snippet: Some("SQL error".to_string()),
            description: "Test vuln description".to_string(),
            solution: "Remediate SQL injection".to_string(),
            reference_urls: vec!["https://owasp.org".to_string()],
            raw_request_header: None,
            raw_response_header: None,
            cvss_score: Some(8.5),
            severity: Some(severity),
        };
        self.vuln_repo
            .upsert_findings(scan_id, app_id, &[input], None)
            .await
            .unwrap();
        let list = self
            .vuln_repo
            .list_with_filters(&infra::traits::VulnFilter::default(), 1, 100)
            .await
            .unwrap();
        let item = list.items.into_iter().find(|v| v.title == title).unwrap();
        self.vuln_repo.get_by_id(item.id).await.unwrap().unwrap()
    }
}
