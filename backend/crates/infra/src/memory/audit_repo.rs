use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::AuditLogRepository;
use shared_types::{RemediationAuditLogResponse, RemediationStatus};

pub struct InMemoryAuditLogRepo {
    logs: RwLock<HashMap<Uuid, Vec<RemediationAuditLogResponse>>>,
}

impl InMemoryAuditLogRepo {
    pub fn new() -> Self {
        Self {
            logs: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryAuditLogRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditLogRepository for InMemoryAuditLogRepo {
    async fn record_log(
        &self,
        vuln_id: Uuid,
        actor_id: Option<Uuid>,
        scan_id: Option<Uuid>,
        action_type: &str,
        old_status: Option<RemediationStatus>,
        new_status: Option<RemediationStatus>,
        comment: Option<&str>,
    ) -> Result<RemediationAuditLogResponse, InfraError> {
        let log_id = Uuid::new_v4();
        let now = Utc::now();

        let log = RemediationAuditLogResponse {
            id: log_id,
            vulnerability_id: vuln_id,
            actor_id,
            scan_id,
            action_type: action_type.to_string(),
            old_status,
            new_status,
            comment: comment.map(|s| s.to_string()),
            created_at: now,
        };

        let mut logs = self.logs.write().await;
        logs.entry(vuln_id).or_default().push(log.clone());

        Ok(log)
    }

    async fn list_by_vuln(&self, vuln_id: Uuid) -> Result<Vec<RemediationAuditLogResponse>, InfraError> {
        let logs = self.logs.read().await;
        let mut list = logs.get(&vuln_id).cloned().unwrap_or_default();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(list)
    }
}
