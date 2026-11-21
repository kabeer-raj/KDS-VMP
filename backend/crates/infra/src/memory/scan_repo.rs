use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::ScanRepository;
use shared_types::{
    PaginatedResponse, ScanDiffSummary, ScanResponse, ScanStatus, SeverityCounts,
    TriggerScanRequest, VulnerabilitySummary,
};

pub struct InMemoryScanRepo {
    scans: RwLock<HashMap<Uuid, ScanResponse>>,
    app_scans: RwLock<HashMap<Uuid, Vec<Uuid>>>,
    scan_findings: RwLock<HashMap<Uuid, Vec<VulnerabilitySummary>>>,
    scan_created_at: RwLock<HashMap<Uuid, DateTime<Utc>>>,
}

impl InMemoryScanRepo {
    pub fn new() -> Self {
        Self {
            scans: RwLock::new(HashMap::new()),
            app_scans: RwLock::new(HashMap::new()),
            scan_findings: RwLock::new(HashMap::new()),
            scan_created_at: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register_scan_findings(&self, scan_id: Uuid, findings: Vec<VulnerabilitySummary>) {
        let mut map = self.scan_findings.write().await;
        map.insert(scan_id, findings);
    }
}

impl Default for InMemoryScanRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanRepository for InMemoryScanRepo {
    async fn create(
        &self,
        app_id: Uuid,
        _triggered_by: Option<Uuid>,
        req: &TriggerScanRequest,
        prev_scan_id: Option<Uuid>,
    ) -> Result<ScanResponse, InfraError> {
        let scan_id = Uuid::new_v4();
        let now = Utc::now();

        let mut diff_summary = ScanDiffSummary::default();
        diff_summary.previous_scan_id = prev_scan_id;

        let scan = ScanResponse {
            id: scan_id,
            application_id: app_id,
            scan_type: req.scan_type,
            status: ScanStatus::Queued,
            progress_percent: 0,
            severity_counts: SeverityCounts::default(),
            diff_summary,
            overall_risk_score: 0.0,
            started_at: None,
            completed_at: None,
            duration_seconds: None,
            error_message: None,
        };

        let mut scans = self.scans.write().await;
        scans.insert(scan_id, scan.clone());

        let mut app_scans = self.app_scans.write().await;
        app_scans.entry(app_id).or_default().push(scan_id);

        let mut created = self.scan_created_at.write().await;
        created.insert(scan_id, now);

        Ok(scan)
    }

    async fn get_by_id(&self, scan_id: Uuid) -> Result<Option<ScanResponse>, InfraError> {
        let scans = self.scans.read().await;
        Ok(scans.get(&scan_id).cloned())
    }

    async fn list_by_app(&self, app_id: Uuid, page: u64, per_page: u64) -> Result<PaginatedResponse<ScanResponse>, InfraError> {
        let scans = self.scans.read().await;
        let app_scans = self.app_scans.read().await;
        let created_map = self.scan_created_at.read().await;

        let empty = Vec::new();
        let scan_ids = app_scans.get(&app_id).unwrap_or(&empty);

        let mut app_scan_list: Vec<ScanResponse> = scan_ids
            .iter()
            .filter_map(|id| scans.get(id).cloned())
            .collect();

        app_scan_list.sort_by(|a, b| {
            let a_created = created_map.get(&a.id).cloned().unwrap_or_else(Utc::now);
            let b_created = created_map.get(&b.id).cloned().unwrap_or_else(Utc::now);
            b_created.cmp(&a_created)
        });

        let total = app_scan_list.len() as u64;
        let per_page = if per_page == 0 { 20 } else { per_page };
        let page = if page == 0 { 1 } else { page };
        let total_pages = (total + per_page - 1) / per_page;

        let start = ((page - 1) * per_page) as usize;
        let items = if start < app_scan_list.len() {
            let end = (start + per_page as usize).min(app_scan_list.len());
            app_scan_list[start..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(PaginatedResponse {
            items,
            page,
            per_page,
            total,
            total_pages,
        })
    }

    async fn update_status(&self, scan_id: Uuid, status: ScanStatus, error_message: Option<String>) -> Result<(), InfraError> {
        let mut scans = self.scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            scan.status = status;
            if let Some(err) = error_message {
                scan.error_message = Some(err);
            }
            match status {
                ScanStatus::Spidering | ScanStatus::ActiveScanning => {
                    if scan.started_at.is_none() {
                        scan.started_at = Some(Utc::now());
                    }
                }
                ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled => {
                    let now = Utc::now();
                    scan.completed_at = Some(now);
                    if let Some(started) = scan.started_at {
                        scan.duration_seconds = Some((now - started).num_seconds().max(0) as i32);
                    }
                    if status == ScanStatus::Completed {
                        scan.progress_percent = 100;
                    }
                }
                _ => {}
            }
            Ok(())
        } else {
            Err(InfraError::NotFound(format!("Scan {} not found", scan_id)))
        }
    }

    async fn update_progress(&self, scan_id: Uuid, progress_percent: u8) -> Result<(), InfraError> {
        let mut scans = self.scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            scan.progress_percent = progress_percent.min(100);
            Ok(())
        } else {
            Err(InfraError::NotFound(format!("Scan {} not found", scan_id)))
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
        let mut scans = self.scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            scan.severity_counts = *counts;
            scan.diff_summary = diff.clone();
            scan.overall_risk_score = risk_score;

            if let Some(dur) = duration_seconds {
                scan.duration_seconds = Some(dur);
            }

            Ok(())
        } else {
            Err(InfraError::NotFound(format!("Scan {} not found", scan_id)))
        }
    }

    async fn cancel(&self, scan_id: Uuid) -> Result<bool, InfraError> {
        let mut scans = self.scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            if scan.status != ScanStatus::Completed && scan.status != ScanStatus::Failed {
                scan.status = ScanStatus::Cancelled;
                scan.completed_at = Some(Utc::now());
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn list_findings(&self, scan_id: Uuid, page: u64, per_page: u64) -> Result<PaginatedResponse<VulnerabilitySummary>, InfraError> {
        let findings_map = self.scan_findings.read().await;
        let empty = Vec::new();
        let findings = findings_map.get(&scan_id).unwrap_or(&empty);

        let total = findings.len() as u64;
        let per_page = if per_page == 0 { 20 } else { per_page };
        let page = if page == 0 { 1 } else { page };
        let total_pages = (total + per_page - 1) / per_page;

        let start = ((page - 1) * per_page) as usize;
        let items = if start < findings.len() {
            let end = (start + per_page as usize).min(findings.len());
            findings[start..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(PaginatedResponse {
            items,
            page,
            per_page,
            total,
            total_pages,
        })
    }

    async fn get_latest_completed_scan_id(&self, app_id: Uuid) -> Result<Option<Uuid>, InfraError> {
        let scans = self.scans.read().await;
        let app_scans = self.app_scans.read().await;
        let created_map = self.scan_created_at.read().await;

        if let Some(scan_ids) = app_scans.get(&app_id) {
            let mut completed: Vec<&ScanResponse> = scan_ids
                .iter()
                .filter_map(|id| scans.get(id))
                .filter(|s| s.status == ScanStatus::Completed)
                .collect();
            completed.sort_by(|a, b| {
                let a_c = created_map.get(&a.id).cloned().unwrap_or_else(Utc::now);
                let b_c = created_map.get(&b.id).cloned().unwrap_or_else(Utc::now);
                b_c.cmp(&a_c)
            });
            Ok(completed.first().map(|s| s.id))
        } else {
            Ok(None)
        }
    }
}
