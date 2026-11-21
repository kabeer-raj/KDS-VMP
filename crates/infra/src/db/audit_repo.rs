use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::AuditLogRepository;
use shared_types::{RemediationAuditLogResponse, RemediationStatus};

pub struct PgAuditLogRepo {
    pool: PgPool,
}

impl PgAuditLogRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditLogRepository for PgAuditLogRepo {
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
        let row = sqlx::query(
            r#"
            INSERT INTO remediation_audit_logs (
                vulnerability_id, actor_id, scan_id, action_type, old_status, new_status, comment
            )
            VALUES ($1, $2, $3, $4, $5::remediation_status, $6::remediation_status, $7)
            RETURNING id, vulnerability_id, actor_id, scan_id, action_type,
                      old_status::text as old_status, new_status::text as new_status,
                      comment, created_at
            "#,
        )
        .bind(vuln_id)
        .bind(actor_id)
        .bind(scan_id)
        .bind(action_type)
        .bind(old_status.map(|s| s.as_str()))
        .bind(new_status.map(|s| s.as_str()))
        .bind(comment)
        .fetch_one(&self.pool)
        .await?;

        let old_st = row
            .get::<Option<String>, _>("old_status")
            .and_then(|s| RemediationStatus::from_str(&s).ok());
        let new_st = row
            .get::<Option<String>, _>("new_status")
            .and_then(|s| RemediationStatus::from_str(&s).ok());

        Ok(RemediationAuditLogResponse {
            id: row.get("id"),
            vulnerability_id: row.get("vulnerability_id"),
            actor_id: row.get("actor_id"),
            scan_id: row.get("scan_id"),
            action_type: row.get("action_type"),
            old_status: old_st,
            new_status: new_st,
            comment: row.get("comment"),
            created_at: row.get("created_at"),
        })
    }

    async fn list_by_vuln(&self, vuln_id: Uuid) -> Result<Vec<RemediationAuditLogResponse>, InfraError> {
        let rows = sqlx::query(
            r#"
            SELECT id, vulnerability_id, actor_id, scan_id, action_type,
                   old_status::text as old_status, new_status::text as new_status,
                   comment, created_at
            FROM remediation_audit_logs
            WHERE vulnerability_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(vuln_id)
        .fetch_all(&self.pool)
        .await?;

        let logs = rows
            .into_iter()
            .map(|r| {
                let old_st = r
                    .get::<Option<String>, _>("old_status")
                    .and_then(|s| RemediationStatus::from_str(&s).ok());
                let new_st = r
                    .get::<Option<String>, _>("new_status")
                    .and_then(|s| RemediationStatus::from_str(&s).ok());

                RemediationAuditLogResponse {
                    id: r.get("id"),
                    vulnerability_id: r.get("vulnerability_id"),
                    actor_id: r.get("actor_id"),
                    scan_id: r.get("scan_id"),
                    action_type: r.get("action_type"),
                    old_status: old_st,
                    new_status: new_st,
                    comment: r.get("comment"),
                    created_at: r.get("created_at"),
                }
            })
            .collect();

        Ok(logs)
    }
}
