use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::ScanRepository;
use shared_types::{
    PaginatedResponse, RemediationStatus, ScanDiffSummary, ScanResponse, ScanStatus, ScanType,
    SeverityCounts, SeverityLevel, TriggerScanRequest, VulnerabilitySummary,
};

pub struct PgScanRepo {
    pool: PgPool,
}

impl PgScanRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_scan(r: &sqlx::postgres::PgRow) -> Result<ScanResponse, InfraError> {
        let scan_type_str: String = r.get("scan_type");
        let scan_type = ScanType::from_str(&scan_type_str)
            .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

        let status_str: String = r.get("status");
        let status = ScanStatus::from_str(&status_str)
            .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

        let progress: i16 = r.get("progress_percent");
        let risk_f64: f64 = r
            .try_get::<f64, _>("overall_risk_score")
            .unwrap_or(0.0);

        let severity_counts = SeverityCounts {
            critical: r.get("critical_count"),
            high: r.get("high_count"),
            medium: r.get("medium_count"),
            low: r.get("low_count"),
            info: r.get("info_count"),
        };

        let diff_summary = ScanDiffSummary {
            previous_scan_id: r.get("previous_scan_id"),
            new_count: r.get("new_findings_count"),
            persistent_count: 0,
            fixed_count: r.get("fixed_findings_count"),
            regressed_count: r.get("regressed_count"),
            risk_score_delta: 0.0,
        };

        Ok(ScanResponse {
            id: r.get("id"),
            application_id: r.get("application_id"),
            scan_type,
            status,
            progress_percent: progress.max(0).min(100) as u8,
            severity_counts,
            diff_summary,
            overall_risk_score: risk_f64,
            started_at: r.get("started_at"),
            completed_at: r.get("completed_at"),
            duration_seconds: r.get("duration_seconds"),
            error_message: r.get("error_message"),
        })
    }
}

#[async_trait]
impl ScanRepository for PgScanRepo {
    async fn create(
        &self,
        app_id: Uuid,
        triggered_by: Option<Uuid>,
        req: &TriggerScanRequest,
        prev_scan_id: Option<Uuid>,
    ) -> Result<ScanResponse, InfraError> {
        let row = sqlx::query(
            r#"
            INSERT INTO scans (
                application_id, triggered_by, previous_scan_id, scan_type, status, progress_percent
            )
            VALUES ($1, $2, $3, $4::scan_type, 'queued'::scan_status, 0)
            RETURNING id, application_id, previous_scan_id, scan_type::text as scan_type,
                      status::text as status, progress_percent, error_message,
                      critical_count, high_count, medium_count, low_count, info_count,
                      new_findings_count, fixed_findings_count, regressed_count,
                      overall_risk_score::float8 as overall_risk_score,
                      started_at, completed_at, duration_seconds
            "#,
        )
        .bind(app_id)
        .bind(triggered_by)
        .bind(prev_scan_id)
        .bind(req.scan_type.as_str())
        .fetch_one(&self.pool)
        .await?;

        Self::row_to_scan(&row)
    }

    async fn get_by_id(&self, scan_id: Uuid) -> Result<Option<ScanResponse>, InfraError> {
        let row = sqlx::query(
            r#"
            SELECT id, application_id, previous_scan_id, scan_type::text as scan_type,
                   status::text as status, progress_percent, error_message,
                   critical_count, high_count, medium_count, low_count, info_count,
                   new_findings_count, fixed_findings_count, regressed_count,
                   overall_risk_score::float8 as overall_risk_score,
                   started_at, completed_at, duration_seconds
            FROM scans
            WHERE id = $1
            "#,
        )
        .bind(scan_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            Ok(Some(Self::row_to_scan(&r)?))
        } else {
            Ok(None)
        }
    }

    async fn list_by_app(&self, app_id: Uuid, page: u64, per_page: u64) -> Result<PaginatedResponse<ScanResponse>, InfraError> {
        let count_row = sqlx::query("SELECT COUNT(*) as count FROM scans WHERE application_id = $1")
            .bind(app_id)
            .fetch_one(&self.pool)
            .await?;
        let total: i64 = count_row.get("count");
        let total = total as u64;

        let per_page = if per_page == 0 { 20 } else { per_page };
        let page = if page == 0 { 1 } else { page };
        let total_pages = (total + per_page - 1) / per_page;
        let offset = ((page - 1) * per_page) as i64;

        let rows = sqlx::query(
            r#"
            SELECT id, application_id, previous_scan_id, scan_type::text as scan_type,
                   status::text as status, progress_percent, error_message,
                   critical_count, high_count, medium_count, low_count, info_count,
                   new_findings_count, fixed_findings_count, regressed_count,
                   overall_risk_score::float8 as overall_risk_score,
                   started_at, completed_at, duration_seconds
            FROM scans
            WHERE application_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(app_id)
        .bind(per_page as i64)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            items.push(Self::row_to_scan(&r)?);
        }

        Ok(PaginatedResponse {
            items,
            page,
            per_page,
            total,
            total_pages,
        })
    }

    async fn update_status(&self, scan_id: Uuid, status: ScanStatus, error_message: Option<String>) -> Result<(), InfraError> {
        let rows_affected = match status {
            ScanStatus::Spidering | ScanStatus::ActiveScanning => {
                sqlx::query(
                    r#"
                    UPDATE scans
                    SET status = $1::scan_status,
                        started_at = COALESCE(started_at, NOW()),
                        error_message = COALESCE($2, error_message)
                    WHERE id = $3
                    "#,
                )
                .bind(status.as_str())
                .bind(error_message)
                .bind(scan_id)
                .execute(&self.pool)
                .await?
                .rows_affected()
            }
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled => {
                sqlx::query(
                    r#"
                    UPDATE scans
                    SET status = $1::scan_status,
                        completed_at = NOW(),
                        duration_seconds = EXTRACT(EPOCH FROM (NOW() - COALESCE(started_at, NOW())))::int,
                        progress_percent = CASE WHEN $1 = 'completed' THEN 100 ELSE progress_percent END,
                        error_message = COALESCE($2, error_message)
                    WHERE id = $3
                    "#,
                )
                .bind(status.as_str())
                .bind(error_message)
                .bind(scan_id)
                .execute(&self.pool)
                .await?
                .rows_affected()
            }
            _ => {
                sqlx::query(
                    r#"
                    UPDATE scans
                    SET status = $1::scan_status,
                        error_message = COALESCE($2, error_message)
                    WHERE id = $3
                    "#,
                )
                .bind(status.as_str())
                .bind(error_message)
                .bind(scan_id)
                .execute(&self.pool)
                .await?
                .rows_affected()
            }
        };

        if rows_affected == 0 {
            Err(InfraError::NotFound(format!("Scan {} not found", scan_id)))
        } else {
            Ok(())
        }
    }

    async fn update_progress(&self, scan_id: Uuid, progress_percent: u8) -> Result<(), InfraError> {
        let clamped = progress_percent.min(100) as i16;
        let rows_affected = sqlx::query("UPDATE scans SET progress_percent = $1 WHERE id = $2")
            .bind(clamped)
            .bind(scan_id)
            .execute(&self.pool)
            .await?
            .rows_affected();

        if rows_affected == 0 {
            Err(InfraError::NotFound(format!("Scan {} not found", scan_id)))
        } else {
            Ok(())
        }
    }

    async fn update_metrics(
        &self,
        scan_id: Uuid,
        counts: &SeverityCounts,
        diff: &ScanDiffSummary,
        risk_score: f64,
        duration_seconds: Option<i32>,
    ) -> Result<(), InfraError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE scans
            SET total_findings = $1, critical_count = $2, high_count = $3,
                medium_count = $4, low_count = $5, info_count = $6,
                new_findings_count = $7, fixed_findings_count = $8, regressed_count = $9,
                overall_risk_score = $10,
                duration_seconds = COALESCE($11, duration_seconds)
            WHERE id = $12
            "#,
        )
        .bind(counts.total())
        .bind(counts.critical)
        .bind(counts.high)
        .bind(counts.medium)
        .bind(counts.low)
        .bind(counts.info)
        .bind(diff.new_count)
        .bind(diff.fixed_count)
        .bind(diff.regressed_count)
        .bind(risk_score)
        .bind(duration_seconds)
        .bind(scan_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows_affected == 0 {
            Err(InfraError::NotFound(format!("Scan {} not found", scan_id)))
        } else {
            Ok(())
        }
    }

    async fn cancel(&self, scan_id: Uuid) -> Result<bool, InfraError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE scans
            SET status = 'cancelled'::scan_status, completed_at = NOW()
            WHERE id = $1 AND status NOT IN ('completed', 'failed')
            "#,
        )
        .bind(scan_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(rows_affected > 0)
    }

    async fn list_findings(&self, scan_id: Uuid, page: u64, per_page: u64) -> Result<PaginatedResponse<VulnerabilitySummary>, InfraError> {
        let count_row = sqlx::query("SELECT COUNT(*) as count FROM scan_findings WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_one(&self.pool)
            .await?;
        let total: i64 = count_row.get("count");
        let total = total as u64;

        let per_page = if per_page == 0 { 20 } else { per_page };
        let page = if page == 0 { 1 } else { page };
        let total_pages = (total + per_page - 1) / per_page;
        let offset = ((page - 1) * per_page) as i64;

        let rows = sqlx::query(
            r#"
            SELECT v.id, v.application_id, v.fingerprint, v.title, v.owasp_category, v.cwe_id,
                   sf.severity_at_scan::text as severity, sf.cvss_at_scan::float8 as cvss_score,
                   v.status::text as status, v.http_method, v.normalized_path, v.affected_param,
                   v.assigned_to, v.seen_count, v.last_seen_at
            FROM scan_findings sf
            JOIN vulnerabilities v ON sf.vulnerability_id = v.id
            WHERE sf.scan_id = $1
            ORDER BY sf.cvss_at_scan DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(scan_id)
        .bind(per_page as i64)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            let sev_str: String = r.get("severity");
            let severity = SeverityLevel::from_str(&sev_str)
                .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

            let stat_str: String = r.get("status");
            let status = RemediationStatus::from_str(&stat_str)
                .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

            items.push(VulnerabilitySummary {
                id: r.get("id"),
                application_id: r.get("application_id"),
                fingerprint: r.get("fingerprint"),
                title: r.get("title"),
                owasp_category: r.get("owasp_category"),
                cwe_id: r.get("cwe_id"),
                severity,
                cvss_score: r.get("cvss_score"),
                status,
                http_method: r.get("http_method"),
                normalized_path: r.get("normalized_path"),
                affected_param: r.get("affected_param"),
                assigned_to: r.get("assigned_to"),
                seen_count: r.get("seen_count"),
                last_seen_at: r.get("last_seen_at"),
            });
        }

        Ok(PaginatedResponse {
            items,
            page,
            per_page,
            total,
            total_pages,
        })
    }

    async fn get_latest_completed_scan_id(&self, app_id: Uuid) -> Result<Option<Uuid>, InfraError> {
        let row = sqlx::query(
            r#"
            SELECT id
            FROM scans
            WHERE application_id = $1 AND status = 'completed'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.get("id")))
    }
}
