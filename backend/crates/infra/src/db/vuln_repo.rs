use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

use core_domain::classifier::classify_owasp;
use core_domain::deduplicator::{generate_fingerprint, normalize_url_path};
use core_domain::diff_engine::{
    diff_scans, FindingFingerprint, FindingLifecycleState, ScanDiffResult,
};
use shared_types::{
    BulkUpdateVulnsRequest, DiffClassification, HttpEvidence, PaginatedResponse,
    RemediationAuditLogResponse, RemediationStatus, SeverityLevel, UpdateVulnerabilityRequest,
    VulnerabilityDetail, VulnerabilitySummary,
};

use crate::error::InfraError;
use crate::traits::{FindingIngestionInput, VulnFilter, VulnRepository};

pub struct PgVulnRepo {
    pool: PgPool,
}

impl PgVulnRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_summary(r: &sqlx::postgres::PgRow) -> Result<VulnerabilitySummary, InfraError> {
        let sev_str: String = r.get("severity");
        let severity = SeverityLevel::from_str(&sev_str)
            .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

        let stat_str: String = r.get("status");
        let status = RemediationStatus::from_str(&stat_str)
            .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

        let cvss_f64: f64 = r
            .try_get::<f64, _>("cvss_score")
            .unwrap_or(0.0);

        Ok(VulnerabilitySummary {
            id: r.get("id"),
            application_id: r.get("application_id"),
            fingerprint: r.get("fingerprint"),
            title: r.get("title"),
            owasp_category: r.get("owasp_category"),
            cwe_id: r.get("cwe_id"),
            severity,
            cvss_score: cvss_f64,
            status,
            http_method: r.get("http_method"),
            normalized_path: r.get("normalized_path"),
            affected_param: r.get("affected_param"),
            assigned_to: r.get("assigned_to"),
            seen_count: r.get("seen_count"),
            last_seen_at: r.get("last_seen_at"),
        })
    }
}

#[async_trait]
impl VulnRepository for PgVulnRepo {
    async fn upsert_findings(
        &self,
        scan_id: Uuid,
        app_id: Uuid,
        raw_findings: &[FindingIngestionInput],
        prev_scan_id: Option<Uuid>,
    ) -> Result<ScanDiffResult, InfraError> {
        // 1. Process current raw findings & deduplicate by fingerprint
        let mut curr_unique_map: HashMap<String, (FindingIngestionInput, String, f64, SeverityLevel)> =
            HashMap::new();

        for raw in raw_findings {
            let norm_path = normalize_url_path(&raw.affected_url);
            let fp = generate_fingerprint(
                &app_id,
                &raw.zap_plugin_id,
                &raw.affected_url,
                raw.affected_param.as_deref(),
                &raw.http_method,
            );
            let cvss = raw.cvss_score.unwrap_or_else(|| match raw.severity {
                Some(SeverityLevel::Critical) => 9.5,
                Some(SeverityLevel::High) => 8.0,
                Some(SeverityLevel::Medium) => 5.5,
                Some(SeverityLevel::Low) => 3.0,
                Some(SeverityLevel::Info) | None => 0.0,
            });
            let sev = raw.severity.unwrap_or_else(|| match cvss {
                s if s >= 9.0 => SeverityLevel::Critical,
                s if s >= 7.0 => SeverityLevel::High,
                s if s >= 4.0 => SeverityLevel::Medium,
                s if s > 0.0 => SeverityLevel::Low,
                _ => SeverityLevel::Info,
            });

            curr_unique_map.entry(fp).or_insert((raw.clone(), norm_path, cvss, sev));
        }

        // 2. Fetch existing statuses for current fingerprints in database
        let mut curr_fingerprints: Vec<FindingFingerprint> = Vec::with_capacity(curr_unique_map.len());
        for (fp, (_, _, cvss, _)) in &curr_unique_map {
            let existing_row = sqlx::query(
                "SELECT status::text as status FROM vulnerabilities WHERE application_id = $1 AND fingerprint = $2",
            )
            .bind(app_id)
            .bind(fp)
            .fetch_optional(&self.pool)
            .await?;

            let status = if let Some(r) = existing_row {
                let stat_str: String = r.get("status");
                RemediationStatus::from_str(&stat_str).unwrap_or(RemediationStatus::Open)
            } else {
                RemediationStatus::Open
            };

            curr_fingerprints.push(
                FindingFingerprint::new(fp.clone())
                    .with_status(status)
                    .with_cvss(*cvss),
            );
        }

        // 3. Fetch previous scan fingerprints if prev_scan_id is present
        let mut prev_fingerprints: Vec<FindingFingerprint> = Vec::new();
        if let Some(prev_id) = prev_scan_id {
            let rows = sqlx::query(
                r#"
                SELECT v.fingerprint, v.status::text as status, sf.cvss_at_scan::float8 as cvss_score
                FROM scan_findings sf
                JOIN vulnerabilities v ON sf.vulnerability_id = v.id
                WHERE sf.scan_id = $1
                "#,
            )
            .bind(prev_id)
            .fetch_all(&self.pool)
            .await?;

            for r in rows {
                let stat_str: String = r.get("status");
                let status = RemediationStatus::from_str(&stat_str).unwrap_or(RemediationStatus::Open);
                let fp: String = r.get("fingerprint");
                let cvss: f64 = r.get("cvss_score");
                prev_fingerprints.push(
                    FindingFingerprint::new(fp)
                        .with_status(status)
                        .with_cvss(cvss),
                );
            }
        }

        // 4. Run scan diff
        let diff_result = diff_scans(&prev_fingerprints, &curr_fingerprints);

        // 5. Begin transaction to commit all upserts, findings, and audit logs
        let mut tx = self.pool.begin().await?;

        for (fp, (raw, norm_path, cvss, sev)) in curr_unique_map {
            let diff_item = diff_result.items.iter().find(|i| i.fingerprint == fp);
            let diff_state = diff_item
                .and_then(|i| i.diff_classification)
                .unwrap_or(DiffClassification::New);
            let owasp = classify_owasp(raw.cwe_id, &raw.zap_plugin_id);

            // Atomic upsert
            let upsert_row = sqlx::query(
                r#"
                INSERT INTO vulnerabilities (
                    application_id, fingerprint, zap_plugin_id, title, cwe_id, wasc_id,
                    owasp_category, severity, cvss_score, cvss_vector, confidence,
                    http_method, affected_url, normalized_path, affected_param,
                    description, solution, reference_urls, first_seen_scan_id, last_seen_scan_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::severity_level, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $19)
                ON CONFLICT (application_id, fingerprint) DO UPDATE SET
                    last_seen_scan_id = EXCLUDED.last_seen_scan_id,
                    last_seen_at      = NOW(),
                    seen_count        = vulnerabilities.seen_count + 1,
                    status = CASE
                        WHEN vulnerabilities.status IN ('resolved', 'verified_fixed')
                        THEN 'regressed'::remediation_status
                        ELSE vulnerabilities.status
                    END
                RETURNING id, status::text as status
                "#,
            )
            .bind(app_id)
            .bind(&fp)
            .bind(&raw.zap_plugin_id)
            .bind(&raw.title)
            .bind(raw.cwe_id)
            .bind(raw.wasc_id)
            .bind(owasp)
            .bind(sev.as_str())
            .bind(cvss)
            .bind(None::<String>)
            .bind(&raw.confidence)
            .bind(&raw.http_method)
            .bind(&raw.affected_url)
            .bind(&norm_path)
            .bind(&raw.affected_param)
            .bind(&raw.description)
            .bind(&raw.solution)
            .bind(&raw.reference_urls)
            .bind(scan_id)
            .fetch_one(&mut *tx)
            .await?;

            let vuln_id: Uuid = upsert_row.get("id");
            let final_status_str: String = upsert_row.get("status");

            // Record regression audit log if regressed
            if final_status_str == "regressed" {
                if let Some(item) = diff_item {
                    if item.lifecycle_state == FindingLifecycleState::Regressed {
                        let _ = sqlx::query(
                            r#"
                            INSERT INTO remediation_audit_logs (
                                vulnerability_id, scan_id, action_type, old_status, new_status, comment
                            )
                            VALUES ($1, $2, 'status_change', $3::remediation_status, 'regressed'::remediation_status, $4)
                            "#,
                        )
                        .bind(vuln_id)
                        .bind(scan_id)
                        .bind(item.previous_status.map(|s| s.as_str()))
                        .bind("Vulnerability re-detected in subsequent scan (regression)")
                        .execute(&mut *tx)
                        .await;
                    }
                }
            }

            // Record junction entry in scan_findings
            let _ = sqlx::query(
                r#"
                INSERT INTO scan_findings (
                    scan_id, vulnerability_id, diff_state, severity_at_scan, cvss_at_scan,
                    attack_payload, evidence_snippet, raw_request_header, raw_response_header
                )
                VALUES ($1, $2, $3::diff_classification, $4::severity_level, $5, $6, $7, $8, $9)
                ON CONFLICT (scan_id, vulnerability_id) DO NOTHING
                "#,
            )
            .bind(scan_id)
            .bind(vuln_id)
            .bind(diff_state.as_str())
            .bind(sev.as_str())
            .bind(cvss)
            .bind(&raw.attack_payload)
            .bind(&raw.evidence_snippet)
            .bind(&raw.raw_request_header)
            .bind(&raw.raw_response_header)
            .execute(&mut *tx)
            .await?;
        }

        // 6. Handle auto-verified fixed vulnerabilities
        for item in &diff_result.items {
            if item.lifecycle_state == FindingLifecycleState::Fixed {
                let updated = sqlx::query(
                    r#"
                    UPDATE vulnerabilities
                    SET status = 'verified_fixed'::remediation_status, resolved_at = NOW()
                    WHERE application_id = $1 AND fingerprint = $2 AND status IN ('open', 'in_progress', 'resolved', 'regressed')
                    RETURNING id
                    "#,
                )
                .bind(app_id)
                .bind(&item.fingerprint)
                .fetch_optional(&mut *tx)
                .await?;

                if let Some(r) = updated {
                    let vid: Uuid = r.get("id");
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO remediation_audit_logs (
                            vulnerability_id, scan_id, action_type, old_status, new_status, comment
                        )
                        VALUES ($1, $2, 'status_change', $3::remediation_status, 'verified_fixed'::remediation_status, $4)
                        "#,
                    )
                    .bind(vid)
                    .bind(scan_id)
                    .bind(item.previous_status.map(|s| s.as_str()))
                    .bind("Automatically verified as fixed: finding absent in subsequent scan")
                    .execute(&mut *tx)
                    .await;
                }
            }
        }

        tx.commit().await?;

        Ok(diff_result)
    }

    async fn list_with_filters(&self, filter: &VulnFilter, page: u64, per_page: u64) -> Result<PaginatedResponse<VulnerabilitySummary>, InfraError> {
        let count_row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM vulnerabilities
            WHERE ($1::uuid IS NULL OR application_id = $1)
              AND ($2::text IS NULL OR severity = $2::severity_level)
              AND ($3::text IS NULL OR status = $3::remediation_status)
              AND ($4::varchar IS NULL OR owasp_category = $4)
              AND ($5::uuid IS NULL OR assigned_to = $5)
              AND ($6::text IS NULL OR title ILIKE '%' || $6 || '%' OR description ILIKE '%' || $6 || '%' OR affected_url ILIKE '%' || $6 || '%')
            "#,
        )
        .bind(filter.app_id)
        .bind(filter.severity.map(|s| s.as_str()))
        .bind(filter.status.map(|s| s.as_str()))
        .bind(&filter.owasp_category)
        .bind(filter.assigned_to)
        .bind(&filter.search)
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
            SELECT id, application_id, fingerprint, title, owasp_category, cwe_id,
                   severity::text as severity, cvss_score::float8 as cvss_score, status::text as status,
                   http_method, normalized_path, affected_param, assigned_to, seen_count, last_seen_at
            FROM vulnerabilities
            WHERE ($1::uuid IS NULL OR application_id = $1)
              AND ($2::text IS NULL OR severity = $2::severity_level)
              AND ($3::text IS NULL OR status = $3::remediation_status)
              AND ($4::varchar IS NULL OR owasp_category = $4)
              AND ($5::uuid IS NULL OR assigned_to = $5)
              AND ($6::text IS NULL OR title ILIKE '%' || $6 || '%' OR description ILIKE '%' || $6 || '%' OR affected_url ILIKE '%' || $6 || '%')
            ORDER BY last_seen_at DESC
            LIMIT $7 OFFSET $8
            "#,
        )
        .bind(filter.app_id)
        .bind(filter.severity.map(|s| s.as_str()))
        .bind(filter.status.map(|s| s.as_str()))
        .bind(&filter.owasp_category)
        .bind(filter.assigned_to)
        .bind(&filter.search)
        .bind(per_page as i64)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            items.push(Self::row_to_summary(&r)?);
        }

        Ok(PaginatedResponse {
            items,
            page,
            per_page,
            total,
            total_pages,
        })
    }

    async fn get_by_id(&self, id: Uuid) -> Result<Option<VulnerabilityDetail>, InfraError> {
        let row = sqlx::query(
            r#"
            SELECT id, application_id, fingerprint, zap_plugin_id, title, cwe_id, wasc_id,
                   owasp_category, severity::text as severity, cvss_score::float8 as cvss_score,
                   cvss_vector, confidence, http_method, affected_url, normalized_path, affected_param,
                   description, solution, reference_urls, status::text as status, assigned_to,
                   due_date, seen_count, first_seen_at, last_seen_at, resolved_at
            FROM vulnerabilities
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let sev_str: String = r.get("severity");
            let severity = SeverityLevel::from_str(&sev_str)
                .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

            let stat_str: String = r.get("status");
            let status = RemediationStatus::from_str(&stat_str)
                .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

            let summary = VulnerabilitySummary {
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
            };

            // Fetch latest evidence from scan_findings
            let evidence_row = sqlx::query(
                r#"
                SELECT scan_id, diff_state::text as diff_state, attack_payload, evidence_snippet,
                       raw_request_header, raw_response_header
                FROM scan_findings
                WHERE vulnerability_id = $1
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

            let latest_evidence = evidence_row.and_then(|er| {
                let diff_str: String = er.get("diff_state");
                let diff_state = DiffClassification::from_str(&diff_str).ok()?;
                Some(HttpEvidence {
                    scan_id: er.get("scan_id"),
                    diff_state,
                    attack_payload: er.get("attack_payload"),
                    evidence_snippet: er.get("evidence_snippet"),
                    raw_request_header: er.get("raw_request_header"),
                    raw_response_header: er.get("raw_response_header"),
                })
            });

            Ok(Some(VulnerabilityDetail {
                summary,
                zap_plugin_id: r.get("zap_plugin_id"),
                wasc_id: r.get("wasc_id"),
                cvss_vector: r.get("cvss_vector"),
                confidence: r.get("confidence"),
                affected_url: r.get("affected_url"),
                description: r.get("description"),
                solution: r.get("solution"),
                reference_urls: r.get("reference_urls"),
                due_date: r.get("due_date"),
                latest_evidence,
                first_seen_at: r.get("first_seen_at"),
                resolved_at: r.get("resolved_at"),
            }))
        } else {
            Ok(None)
        }
    }

    async fn update_triage(&self, id: Uuid, req: &UpdateVulnerabilityRequest, actor_id: Option<Uuid>) -> Result<Option<VulnerabilityDetail>, InfraError> {
        let current = self.get_by_id(id).await?;
        let current = match current {
            Some(c) => c,
            None => return Ok(None),
        };

        let mut tx = self.pool.begin().await?;

        let new_status = req.status.unwrap_or(current.summary.status);
        let new_severity = req.severity.unwrap_or(current.summary.severity);
        let assigned_to = req.assigned_to.or(current.summary.assigned_to);
        let due_date = req.due_date.or(current.due_date);

        let resolved_at = if new_status == RemediationStatus::Resolved || new_status == RemediationStatus::VerifiedFixed {
            Some(Utc::now())
        } else {
            current.resolved_at
        };

        let _ = sqlx::query(
            r#"
            UPDATE vulnerabilities
            SET status = $1::remediation_status,
                severity = $2::severity_level,
                assigned_to = $3,
                due_date = $4,
                resolved_at = $5,
                updated_at = NOW()
            WHERE id = $6
            "#,
        )
        .bind(new_status.as_str())
        .bind(new_severity.as_str())
        .bind(assigned_to)
        .bind(due_date)
        .bind(resolved_at)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        if req.status.is_some() && req.status != Some(current.summary.status) {
            let _ = sqlx::query(
                r#"
                INSERT INTO remediation_audit_logs (
                    vulnerability_id, actor_id, action_type, old_status, new_status, comment
                )
                VALUES ($1, $2, 'status_change', $3::remediation_status, $4::remediation_status, $5)
                "#,
            )
            .bind(id)
            .bind(actor_id)
            .bind(current.summary.status.as_str())
            .bind(new_status.as_str())
            .bind(&req.comment)
            .execute(&mut *tx)
            .await;
        } else if let Some(ref comment) = req.comment {
            let _ = sqlx::query(
                r#"
                INSERT INTO remediation_audit_logs (
                    vulnerability_id, actor_id, action_type, comment
                )
                VALUES ($1, $2, 'comment', $3)
                "#,
            )
            .bind(id)
            .bind(actor_id)
            .bind(comment)
            .execute(&mut *tx)
            .await;
        }

        tx.commit().await?;

        self.get_by_id(id).await
    }

    async fn bulk_update(&self, req: &BulkUpdateVulnsRequest, actor_id: Option<Uuid>) -> Result<usize, InfraError> {
        let mut count = 0;
        let triage_req = UpdateVulnerabilityRequest {
            status: req.status,
            severity: req.severity,
            assigned_to: req.assigned_to,
            due_date: None,
            comment: req.comment.clone(),
        };

        for &id in &req.vuln_ids {
            if self.update_triage(id, &triage_req, actor_id).await?.is_some() {
                count += 1;
            }
        }

        Ok(count)
    }

    async fn get_history(&self, id: Uuid) -> Result<Vec<RemediationAuditLogResponse>, InfraError> {
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
        .bind(id)
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

    async fn add_comment(&self, id: Uuid, comment: &str, actor_id: Option<Uuid>) -> Result<RemediationAuditLogResponse, InfraError> {
        let row = sqlx::query(
            r#"
            INSERT INTO remediation_audit_logs (
                vulnerability_id, actor_id, action_type, comment
            )
            VALUES ($1, $2, 'comment', $3)
            RETURNING id, vulnerability_id, actor_id, scan_id, action_type,
                      old_status::text as old_status, new_status::text as new_status,
                      comment, created_at
            "#,
        )
        .bind(id)
        .bind(actor_id)
        .bind(comment)
        .fetch_one(&self.pool)
        .await?;

        Ok(RemediationAuditLogResponse {
            id: row.get("id"),
            vulnerability_id: row.get("vulnerability_id"),
            actor_id: row.get("actor_id"),
            scan_id: row.get("scan_id"),
            action_type: row.get("action_type"),
            old_status: None,
            new_status: None,
            comment: row.get("comment"),
            created_at: row.get("created_at"),
        })
    }
}
