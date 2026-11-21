use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::engine::ScanWorkerEngine;
use crate::error::ScanWorkerError;
use crate::queue::ScanJob;
use crate::scheduler::ScheduledScanEvaluator;

/// Evaluates recurring cron schedules for applications and enqueues due scans.
pub async fn run_scheduled_cron_evaluator(
    engine: &ScanWorkerEngine,
    now: DateTime<Utc>,
) -> Result<Vec<Uuid>, ScanWorkerError> {
    let evaluator = ScheduledScanEvaluator::new(engine.app_repo.clone(), engine.scan_repo.clone());
    let triggered = evaluator.evaluate_due_scans(now).await?;

    let mut scan_ids = Vec::with_capacity(triggered.len());
    for (app_id, scan) in triggered {
        scan_ids.push(scan.id);
        let job = ScanJob {
            scan_id: scan.id,
            application_id: app_id,
            target_url: "".to_string(),
            scan_type: scan.scan_type,
            custom_headers: None,
        };
        engine.job_queue.enqueue(job).await;
    }

    Ok(scan_ids)
}
