pub mod cron;

use std::sync::Arc;
use chrono::{DateTime, Utc};
use infra::traits::{AppRepository, ScanRepository};
use shared_types::enums::{ScanStatus, ScanType};
use shared_types::scan::{ScanResponse, TriggerScanRequest};
use uuid::Uuid;

pub use cron::CronExpression;
use crate::error::ScanWorkerError;

/// Evaluator that examines configured application schedules and triggers recurring scans when due.
pub struct ScheduledScanEvaluator {
    app_repo: Arc<dyn AppRepository>,
    scan_repo: Arc<dyn ScanRepository>,
}

impl ScheduledScanEvaluator {
    pub fn new(app_repo: Arc<dyn AppRepository>, scan_repo: Arc<dyn ScanRepository>) -> Self {
        Self { app_repo, scan_repo }
    }

    /// Evaluates all registered applications, checks whether their cron schedules are due,
    /// verifies authorization, skips apps with active scans, and dispatches queued scans for due targets.
    pub async fn evaluate_due_scans(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(Uuid, ScanResponse)>, ScanWorkerError> {
        let apps = self.app_repo.list(None, None).await?;
        let mut triggered = Vec::new();

        for app in apps {
            let cron_expr_str = match &app.cron_schedule {
                Some(expr) if !expr.trim().is_empty() => expr.trim(),
                _ => continue,
            };

            // Only run scans for authorized applications
            if !app.is_authorized {
                tracing::warn!(app_id = %app.id, app_name = %app.name, "Skipping scheduled scan: target is not authorized");
                continue;
            }

            // Parse and validate cron expression
            let cron = match CronExpression::parse(cron_expr_str) {
                Ok(c) => c,
                Err(err) => {
                    tracing::warn!(app_id = %app.id, schedule = %cron_expr_str, error = %err, "Invalid cron schedule expression");
                    continue;
                }
            };

            // Check if scan is due based on last_scanned_at and current time
            if !cron.is_due(app.last_scanned_at, now) {
                continue;
            }

            // Check if application currently has an active running scan
            let scan_page = self.scan_repo.list_by_app(app.id, 1, 20).await?;
            let has_active = scan_page.items.iter().any(|s| {
                matches!(
                    s.status,
                    ScanStatus::Queued
                        | ScanStatus::Spidering
                        | ScanStatus::ActiveScanning
                        | ScanStatus::Ingesting
                )
            });

            if has_active {
                tracing::info!(app_id = %app.id, app_name = %app.name, "Skipping scheduled scan: application already has an active scan in progress");
                continue;
            }

            // Fetch previous completed scan for diffing
            let prev_scan_id = self.scan_repo.get_latest_completed_scan_id(app.id).await?;

            // Trigger new queued scan
            let trigger_req = TriggerScanRequest {
                scan_type: ScanType::FullActive,
                max_duration_minutes: Some(60),
                custom_headers: None,
            };

            let scan = self
                .scan_repo
                .create(app.id, None, &trigger_req, prev_scan_id)
                .await?;

            tracing::info!(app_id = %app.id, scan_id = %scan.id, "Dispatched scheduled automated scan");
            triggered.push((app.id, scan));
        }

        Ok(triggered)
    }
}
