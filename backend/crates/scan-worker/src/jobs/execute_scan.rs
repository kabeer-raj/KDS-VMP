use shared_types::scan::ScanResponse;
use uuid::Uuid;

use crate::engine::ScanWorkerEngine;
use crate::error::ScanWorkerError;
use crate::queue::ScanJob;

/// Job executor for an individual scan run.
pub async fn execute_scan_job(
    engine: &ScanWorkerEngine,
    job: &ScanJob,
) -> Result<ScanResponse, ScanWorkerError> {
    engine.execute_job(job.clone()).await
}

/// Executes a scan directly by scan ID.
pub async fn execute_scan_by_id(
    engine: &ScanWorkerEngine,
    scan_id: Uuid,
) -> Result<ScanResponse, ScanWorkerError> {
    engine.execute_scan(scan_id).await
}
