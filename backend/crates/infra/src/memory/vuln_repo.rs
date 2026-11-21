use async_trait::async_trait;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
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

pub struct InMemoryVulnRepo {
    vulns: RwLock<HashMap<Uuid, VulnerabilityDetail>>,
    app_fingerprints: RwLock<HashMap<(Uuid, String), Uuid>>, // (app_id, fingerprint) -> vuln_id
    scan_findings: RwLock<HashMap<(Uuid, Uuid), HttpEvidence>>, // (scan_id, vuln_id) -> evidence
    scan_vuln_ids: RwLock<HashMap<Uuid, Vec<Uuid>>>,         // scan_id -> vuln_ids
    audit_logs: RwLock<HashMap<Uuid, Vec<RemediationAuditLogResponse>>>, // vuln_id -> logs
}

impl InMemoryVulnRepo {
    pub fn new() -> Self {
        Self {
            vulns: RwLock::new(HashMap::new()),
            app_fingerprints: RwLock::new(HashMap::new()),
            scan_findings: RwLock::new(HashMap::new()),
            scan_vuln_ids: RwLock::new(HashMap::new()),
            audit_logs: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryVulnRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VulnRepository for InMemoryVulnRepo {
    async fn upsert_findings(
        &self,
        scan_id: Uuid,
        app_id: Uuid,
        raw_findings: &[FindingIngestionInput],
        prev_scan_id: Option<Uuid>,
    ) -> Result<ScanDiffResult, InfraError> {
        let now = Utc::now();

        // 1. Process and compute fingerprints for current raw findings
        let mut curr_items: Vec<(String, FindingIngestionInput, String, f64, SeverityLevel)> =
            Vec::with_capacity(raw_findings.len());

        for raw in raw_findings {
            let normalized_path = normalize_url_path(&raw.affected_url);
            let fingerprint = generate_fingerprint(
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
            let severity = raw.severity.unwrap_or_else(|| match cvss {
                s if s >= 9.0 => SeverityLevel::Critical,
                s if s >= 7.0 => SeverityLevel::High,
                s if s >= 4.0 => SeverityLevel::Medium,
                s if s > 0.0 => SeverityLevel::Low,
                _ => SeverityLevel::Info,
            });

            curr_items.push((fingerprint, raw.clone(), normalized_path, cvss, severity));
        }

        // Deduplicate current findings by fingerprint
        let mut curr_unique_map: HashMap<String, (FindingIngestionInput, String, f64, SeverityLevel)> =
            HashMap::new();
        for (fp, raw, norm_path, cvss, sev) in curr_items {
            curr_unique_map.entry(fp).or_insert((raw, norm_path, cvss, sev));
        }

        let app_fps = self.app_fingerprints.read().await;
        let vulns_read = self.vulns.read().await;

        // 2. Build current scan FindingFingerprint list
        let mut curr_fingerprints: Vec<FindingFingerprint> = Vec::with_capacity(curr_unique_map.len());
        for (fp, (_, _, cvss, _)) in &curr_unique_map {
            let status = if let Some(vuln_id) = app_fps.get(&(app_id, fp.clone())) {
                vulns_read
                    .get(vuln_id)
                    .map(|v| v.summary.status)
                    .unwrap_or(RemediationStatus::Open)
            } else {
                RemediationStatus::Open
            };

            curr_fingerprints.push(
                FindingFingerprint::new(fp.clone())
                    .with_status(status)
                    .with_cvss(*cvss),
            );
        }

        // 3. Build previous scan FindingFingerprint list
        let mut prev_fingerprints: Vec<FindingFingerprint> = Vec::new();
        if let Some(prev_id) = prev_scan_id {
            let scan_vulns = self.scan_vuln_ids.read().await;
            if let Some(prev_ids) = scan_vulns.get(&prev_id) {
                let mut seen_prev_fps = HashSet::new();
                for vid in prev_ids {
                    if let Some(vuln) = vulns_read.get(vid) {
                        if seen_prev_fps.insert(vuln.summary.fingerprint.clone()) {
                            prev_fingerprints.push(
                                FindingFingerprint::new(vuln.summary.fingerprint.clone())
                                    .with_status(vuln.summary.status)
                                    .with_cvss(vuln.summary.cvss_score),
                            );
                        }
                    }
                }
            }
        }

        drop(app_fps);
        drop(vulns_read);

        // 4. Compute scan-to-scan diff
        let diff_result = diff_scans(&prev_fingerprints, &curr_fingerprints);

        // 5. Apply persistence & lifecycle transitions
        let mut vulns_write = self.vulns.write().await;
        let mut app_fps_write = self.app_fingerprints.write().await;
        let mut scan_findings_write = self.scan_findings.write().await;
        let mut scan_vulns_write = self.scan_vuln_ids.write().await;
        let mut audit_logs_write = self.audit_logs.write().await;

        let mut current_scan_vuln_ids = Vec::with_capacity(curr_unique_map.len());

        for (fp, (raw, norm_path, cvss, sev)) in curr_unique_map {
            let diff_item = diff_result.items.iter().find(|i| i.fingerprint == fp);
            let diff_state = diff_item
                .and_then(|i| i.diff_classification)
                .unwrap_or(DiffClassification::New);

            let evidence = HttpEvidence {
                scan_id,
                diff_state,
                attack_payload: raw.attack_payload.clone(),
                evidence_snippet: raw.evidence_snippet.clone(),
                raw_request_header: raw.raw_request_header.clone(),
                raw_response_header: raw.raw_response_header.clone(),
            };

            let vuln_id = if let Some(&existing_id) = app_fps_write.get(&(app_id, fp.clone())) {
                if let Some(v) = vulns_write.get_mut(&existing_id) {
                    v.summary.seen_count += 1;
                    v.summary.last_seen_at = now;
                    v.latest_evidence = Some(evidence.clone());

                    // Check regression
                    if let Some(item) = diff_item {
                        if item.lifecycle_state == FindingLifecycleState::Regressed {
                            let old_status = v.summary.status;
                            v.summary.status = RemediationStatus::Regressed;
                            v.resolved_at = None;

                            // Record regression audit log
                            let log = RemediationAuditLogResponse {
                                id: Uuid::new_v4(),
                                vulnerability_id: existing_id,
                                actor_id: None,
                                scan_id: Some(scan_id),
                                action_type: "status_change".to_string(),
                                old_status: Some(old_status),
                                new_status: Some(RemediationStatus::Regressed),
                                comment: Some("Vulnerability re-detected in subsequent scan (regression)".to_string()),
                                created_at: now,
                            };
                            audit_logs_write.entry(existing_id).or_default().push(log);
                        }
                    }
                }
                existing_id
            } else {
                let new_id = Uuid::new_v4();
                let owasp = classify_owasp(raw.cwe_id, &raw.zap_plugin_id).to_string();

                let summary = VulnerabilitySummary {
                    id: new_id,
                    application_id: app_id,
                    fingerprint: fp.clone(),
                    title: raw.title.clone(),
                    owasp_category: owasp,
                    cwe_id: raw.cwe_id,
                    severity: sev,
                    cvss_score: cvss,
                    status: RemediationStatus::Open,
                    http_method: raw.http_method.clone(),
                    normalized_path: norm_path,
                    affected_param: raw.affected_param.clone(),
                    assigned_to: None,
                    seen_count: 1,
                    last_seen_at: now,
                };

                let detail = VulnerabilityDetail {
                    summary,
                    zap_plugin_id: raw.zap_plugin_id.clone(),
                    wasc_id: raw.wasc_id,
                    cvss_vector: None,
                    confidence: raw.confidence.clone(),
                    affected_url: raw.affected_url.clone(),
                    description: raw.description.clone(),
                    solution: raw.solution.clone(),
                    reference_urls: raw.reference_urls.clone(),
                    due_date: None,
                    latest_evidence: Some(evidence.clone()),
                    first_seen_at: now,
                    resolved_at: None,
                };

                vulns_write.insert(new_id, detail);
                app_fps_write.insert((app_id, fp.clone()), new_id);

                let log = RemediationAuditLogResponse {
                    id: Uuid::new_v4(),
                    vulnerability_id: new_id,
                    actor_id: None,
                    scan_id: Some(scan_id),
                    action_type: "created".to_string(),
                    old_status: None,
                    new_status: Some(RemediationStatus::Open),
                    comment: Some("Vulnerability discovered by automated scan".to_string()),
                    created_at: now,
                };
                audit_logs_write.entry(new_id).or_default().push(log);

                new_id
            };

            scan_findings_write.insert((scan_id, vuln_id), evidence);
            current_scan_vuln_ids.push(vuln_id);
        }

        // 6. Handle auto-verified fixed vulnerabilities
        for item in &diff_result.items {
            if item.lifecycle_state == FindingLifecycleState::Fixed {
                if let Some(&fixed_vuln_id) = app_fps_write.get(&(app_id, item.fingerprint.clone())) {
                    if let Some(v) = vulns_write.get_mut(&fixed_vuln_id) {
                        let old_status = v.summary.status;
                        v.summary.status = RemediationStatus::VerifiedFixed;
                        v.resolved_at = Some(now);

                        let log = RemediationAuditLogResponse {
                            id: Uuid::new_v4(),
                            vulnerability_id: fixed_vuln_id,
                            actor_id: None,
                            scan_id: Some(scan_id),
                            action_type: "status_change".to_string(),
                            old_status: Some(old_status),
                            new_status: Some(RemediationStatus::VerifiedFixed),
                            comment: Some("Automatically verified as fixed: finding absent in subsequent scan".to_string()),
                            created_at: now,
                        };
                        audit_logs_write.entry(fixed_vuln_id).or_default().push(log);
                    }
                }
            }
        }

        scan_vulns_write.insert(scan_id, current_scan_vuln_ids);

        Ok(diff_result)
    }

    async fn list_with_filters(&self, filter: &VulnFilter, page: u64, per_page: u64) -> Result<PaginatedResponse<VulnerabilitySummary>, InfraError> {
        let vulns = self.vulns.read().await;

        let mut items: Vec<VulnerabilitySummary> = vulns
            .values()
            .filter(|v| {
                if let Some(app_id) = filter.app_id {
                    if v.summary.application_id != app_id {
                        return false;
                    }
                }
                if let Some(sev) = filter.severity {
                    if v.summary.severity != sev {
                        return false;
                    }
                }
                if let Some(stat) = filter.status {
                    if v.summary.status != stat {
                        return false;
                    }
                }
                if let Some(ref cat) = filter.owasp_category {
                    if &v.summary.owasp_category != cat {
                        return false;
                    }
                }
                if let Some(assigned) = filter.assigned_to {
                    if v.summary.assigned_to != Some(assigned) {
                        return false;
                    }
                }
                if let Some(ref search) = filter.search {
                    let search_lower = search.to_lowercase();
                    let title_match = v.summary.title.to_lowercase().contains(&search_lower);
                    let desc_match = v.description.to_lowercase().contains(&search_lower);
                    let url_match = v.affected_url.to_lowercase().contains(&search_lower);
                    if !title_match && !desc_match && !url_match {
                        return false;
                    }
                }
                true
            })
            .map(|v| v.summary.clone())
            .collect();

        // Sort
        match filter.sort_by.as_deref() {
            Some("severity") => items.sort_by(|a, b| b.severity.cmp(&a.severity)),
            Some("cvss_score") => items.sort_by(|a, b| {
                b.cvss_score
                    .partial_cmp(&a.cvss_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            Some("title") => items.sort_by(|a, b| a.title.cmp(&b.title)),
            _ => items.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at)),
        }

        if filter.order.as_deref() == Some("asc") {
            items.reverse();
        }

        let total = items.len() as u64;
        let per_page = if per_page == 0 { 20 } else { per_page };
        let page = if page == 0 { 1 } else { page };
        let total_pages = (total + per_page - 1) / per_page;

        let start = ((page - 1) * per_page) as usize;
        let page_items = if start < items.len() {
            let end = (start + per_page as usize).min(items.len());
            items[start..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(PaginatedResponse {
            items: page_items,
            page,
            per_page,
            total,
            total_pages,
        })
    }

    async fn get_by_id(&self, id: Uuid) -> Result<Option<VulnerabilityDetail>, InfraError> {
        let vulns = self.vulns.read().await;
        Ok(vulns.get(&id).cloned())
    }

    async fn update_triage(&self, id: Uuid, req: &UpdateVulnerabilityRequest, actor_id: Option<Uuid>) -> Result<Option<VulnerabilityDetail>, InfraError> {
        let mut vulns = self.vulns.write().await;
        if let Some(v) = vulns.get_mut(&id) {
            let now = Utc::now();
            let mut logs_to_add = Vec::new();

            if let Some(new_status) = req.status {
                if new_status != v.summary.status {
                    let old_status = v.summary.status;
                    v.summary.status = new_status;
                    if new_status == RemediationStatus::Resolved || new_status == RemediationStatus::VerifiedFixed {
                        v.resolved_at = Some(now);
                    } else {
                        v.resolved_at = None;
                    }

                    logs_to_add.push(RemediationAuditLogResponse {
                        id: Uuid::new_v4(),
                        vulnerability_id: id,
                        actor_id,
                        scan_id: None,
                        action_type: "status_change".to_string(),
                        old_status: Some(old_status),
                        new_status: Some(new_status),
                        comment: req.comment.clone(),
                        created_at: now,
                    });
                }
            }

            if let Some(sev) = req.severity {
                if sev != v.summary.severity {
                    v.summary.severity = sev;
                    logs_to_add.push(RemediationAuditLogResponse {
                        id: Uuid::new_v4(),
                        vulnerability_id: id,
                        actor_id,
                        scan_id: None,
                        action_type: "severity_override".to_string(),
                        old_status: None,
                        new_status: None,
                        comment: Some(format!("Severity adjusted to {:?}", sev)),
                        created_at: now,
                    });
                }
            }

            if req.assigned_to.is_some() {
                v.summary.assigned_to = req.assigned_to;
                logs_to_add.push(RemediationAuditLogResponse {
                    id: Uuid::new_v4(),
                    vulnerability_id: id,
                    actor_id,
                    scan_id: None,
                    action_type: "assigned".to_string(),
                    old_status: None,
                    new_status: None,
                    comment: Some("Assignee updated".to_string()),
                    created_at: now,
                });
            }

            if req.due_date.is_some() {
                v.due_date = req.due_date;
            }

            if let Some(ref comment) = req.comment {
                if req.status.is_none() {
                    logs_to_add.push(RemediationAuditLogResponse {
                        id: Uuid::new_v4(),
                        vulnerability_id: id,
                        actor_id,
                        scan_id: None,
                        action_type: "comment".to_string(),
                        old_status: None,
                        new_status: None,
                        comment: Some(comment.clone()),
                        created_at: now,
                    });
                }
            }

            let mut audit_logs = self.audit_logs.write().await;
            for log in logs_to_add {
                audit_logs.entry(id).or_default().push(log);
            }

            Ok(Some(v.clone()))
        } else {
            Ok(None)
        }
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

        for vuln_id in &req.vuln_ids {
            if self.update_triage(*vuln_id, &triage_req, actor_id).await?.is_some() {
                count += 1;
            }
        }

        Ok(count)
    }

    async fn get_history(&self, id: Uuid) -> Result<Vec<RemediationAuditLogResponse>, InfraError> {
        let logs = self.audit_logs.read().await;
        let mut list = logs.get(&id).cloned().unwrap_or_default();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(list)
    }

    async fn add_comment(&self, id: Uuid, comment: &str, actor_id: Option<Uuid>) -> Result<RemediationAuditLogResponse, InfraError> {
        let vulns = self.vulns.read().await;
        if !vulns.contains_key(&id) {
            return Err(InfraError::NotFound(format!("Vulnerability {} not found", id)));
        }

        let log = RemediationAuditLogResponse {
            id: Uuid::new_v4(),
            vulnerability_id: id,
            actor_id,
            scan_id: None,
            action_type: "comment".to_string(),
            old_status: None,
            new_status: None,
            comment: Some(comment.to_string()),
            created_at: Utc::now(),
        };

        let mut logs = self.audit_logs.write().await;
        logs.entry(id).or_default().push(log.clone());

        Ok(log)
    }
}
