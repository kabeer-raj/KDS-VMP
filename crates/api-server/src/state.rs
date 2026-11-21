use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;
use uuid::Uuid;

use infra::memory::{
    InMemoryAppRepo, InMemoryAuditLogRepo, InMemoryPubSub, InMemoryScanRepo, InMemoryUserRepo,
    InMemoryVulnRepo,
};
use infra::pdf::SimplePdfGenerator;
use infra::traits::{
    AppRepository, AuditLogRepository, PdfGenerator, PubSubPort, ScanRepository, UserRepository,
    VulnRepository, ZapClient,
};
use infra::zap::MockZapClient;
use shared_types::UserRole;

use crate::error::AppError;

pub type AuditRepository = dyn AuditLogRepository;
pub type PubSubAdapter = dyn PubSubPort;

#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AppState {
    pub app_repo: Arc<dyn AppRepository>,
    pub scan_repo: Arc<dyn ScanRepository>,
    pub vuln_repo: Arc<dyn VulnRepository>,
    pub user_repo: Arc<dyn UserRepository>,
    pub audit_repo: Arc<dyn AuditLogRepository>,
    pub pubsub_adapter: Arc<dyn PubSubPort>,
    pub pdf_generator: Arc<dyn PdfGenerator>,
    pub zap_client: Arc<dyn ZapClient>,
    pub jwt_secret: String,
    pub refresh_tokens: Arc<RwLock<HashMap<String, RefreshTokenRecord>>>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_repo: Arc<dyn AppRepository>,
        scan_repo: Arc<dyn ScanRepository>,
        vuln_repo: Arc<dyn VulnRepository>,
        user_repo: Arc<dyn UserRepository>,
        audit_repo: Arc<dyn AuditLogRepository>,
        pubsub_adapter: Arc<dyn PubSubPort>,
        pdf_generator: Arc<dyn PdfGenerator>,
        zap_client: Arc<dyn ZapClient>,
        jwt_secret: String,
    ) -> Self {
        Self {
            app_repo,
            scan_repo,
            vuln_repo,
            user_repo,
            audit_repo,
            pubsub_adapter,
            pdf_generator,
            zap_client,
            jwt_secret,
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn new_in_memory() -> Self {
        let jwt_secret = "test_jwt_secret_key_appsec_platform_2026_super_secure".to_string();
        let app_repo = Arc::new(InMemoryAppRepo::new());
        let scan_repo = Arc::new(InMemoryScanRepo::new());
        let vuln_repo = Arc::new(InMemoryVulnRepo::new());
        let user_repo = Arc::new(InMemoryUserRepo::new());
        let audit_repo = Arc::new(InMemoryAuditLogRepo::new());
        let pubsub_adapter = Arc::new(InMemoryPubSub::new());
        let pdf_generator = Arc::new(SimplePdfGenerator::new());
        let zap_client = Arc::new(MockZapClient::new());

        let state = Self::new(
            app_repo,
            scan_repo,
            vuln_repo,
            user_repo,
            audit_repo,
            pubsub_adapter,
            pdf_generator,
            zap_client,
            jwt_secret,
        );

        state
    }

    pub async fn seed_default_users(&self) {
        use crate::middleware::hash_password;

        let users = [
            ("admin@kds.local", "Admin User", "AdminSecret123!", UserRole::Admin),
            ("seceng@kds.local", "Security Engineer", "SecEngSecret123!", UserRole::SecurityEngineer),
            ("dev@kds.local", "Developer User", "DevSecret123!", UserRole::Developer),
            ("auditor@kds.local", "Auditor User", "AuditorSecret123!", UserRole::Auditor),
        ];

        for (email, name, pass, role) in users {
            let pass_hash = hash_password(pass);
            let _ = self.user_repo.create(email, name, &pass_hash, role).await;
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

    pub async fn rotate_refresh_token(
        &self,
        old_token: &str,
        new_token: &str,
        ttl_days: i64,
    ) -> Result<Uuid, AppError> {
        if !old_token.starts_with("refresh_") {
            return Err(AppError::unauthorized(
                "INVALID_REFRESH_TOKEN",
                "Malformed refresh token",
            ));
        }
        let mut map = self.refresh_tokens.write().await;
        let rec = map.remove(old_token).ok_or_else(|| {
            AppError::unauthorized(
                "INVALID_REFRESH_TOKEN",
                "Refresh token not found or revoked",
            )
        })?;
        if rec.expires_at < Utc::now() {
            return Err(AppError::unauthorized(
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
