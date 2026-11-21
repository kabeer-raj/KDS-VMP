use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use uuid::Uuid;

use infra::traits::{AppRepository, PubSubPort, ScanRepository, VulnRepository, ZapClient};
use shared_types::enums::ScanStatus;
use shared_types::scan::ScanResponse;

use crate::error::ScanWorkerError;
use crate::orchestrator::ZapOrchestrator;
use crate::queue::{InMemoryScanJobQueue, ScanJob};
use crate::scheduler::ScheduledScanEvaluator;

/// Background scan engine orchestrating job consumption, execution, and scheduled polling.
pub struct ScanWorkerEngine {
    pub app_repo: Arc<dyn AppRepository>,
    pub scan_repo: Arc<dyn ScanRepository>,
    pub vuln_repo: Arc<dyn VulnRepository>,
    pub zap_client: Arc<dyn ZapClient>,
    pub pubsub: Arc<dyn PubSubPort>,
    pub job_queue: Arc<InMemoryScanJobQueue>,
    pub max_concurrency: usize,
    semaphore: Arc<Semaphore>,
}

impl ScanWorkerEngine {
    pub fn new(
        app_repo: Arc<dyn AppRepository>,
        scan_repo: Arc<dyn ScanRepository>,
        vuln_repo: Arc<dyn VulnRepository>,
        zap_client: Arc<dyn ZapClient>,
        pubsub: Arc<dyn PubSubPort>,
    ) -> Self {
        let max_concurrency = 4;
        Self {
            app_repo,
            scan_repo,
            vuln_repo,
            zap_client,
            pubsub,
            job_queue: Arc::new(InMemoryScanJobQueue::new()),
            max_concurrency,
            semaphore: Arc::new(Semaphore::new(max_concurrency)),
        }
    }

    pub fn with_job_queue(mut self, queue: Arc<InMemoryScanJobQueue>) -> Self {
        self.job_queue = queue;
        self
    }

    pub fn with_max_concurrency(mut self, max: usize) -> Self {
        self.max_concurrency = max;
        self.semaphore = Arc::new(Semaphore::new(max));
        self
    }

    /// Executes a scan by its unique ID through the full ZAP and finding pipeline lifecycle.
    pub async fn execute_scan(&self, scan_id: Uuid) -> Result<ScanResponse, ScanWorkerError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| ScanWorkerError::Other(format!("Semaphore acquire failed: {e}")))?;

        let scan = self
            .scan_repo
            .get_by_id(scan_id)
            .await?
            .ok_or(ScanWorkerError::ScanNotFound(scan_id))?;

        let app = self
            .app_repo
            .get_by_id(scan.application_id)
            .await?
            .ok_or(ScanWorkerError::ApplicationNotFound(scan.application_id))?;

        tracing::info!(scan_id = %scan.id, app_id = %app.id, app_name = %app.name, "Starting scan execution pipeline");

        ZapOrchestrator::orchestrate_scan(
            scan.id,
            &app,
            scan.scan_type,
            None,
            &self.zap_client,
            &self.scan_repo,
            &self.vuln_repo,
            &self.app_repo,
            &self.pubsub,
        )
        .await
    }

    /// Executes a specific ScanJob dequeued from the job queue.
    pub async fn execute_job(&self, job: ScanJob) -> Result<ScanResponse, ScanWorkerError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| ScanWorkerError::Other(format!("Semaphore acquire failed: {e}")))?;

        let scan = self
            .scan_repo
            .get_by_id(job.scan_id)
            .await?
            .ok_or(ScanWorkerError::ScanNotFound(job.scan_id))?;

        let app = self
            .app_repo
            .get_by_id(job.application_id)
            .await?
            .ok_or(ScanWorkerError::ApplicationNotFound(job.application_id))?;

        tracing::info!(scan_id = %scan.id, app_id = %app.id, app_name = %app.name, "Executing scan job from queue");

        ZapOrchestrator::orchestrate_scan(
            job.scan_id,
            &app,
            job.scan_type,
            job.custom_headers,
            &self.zap_client,
            &self.scan_repo,
            &self.vuln_repo,
            &self.app_repo,
            &self.pubsub,
        )
        .await
    }

    /// Consumes and executes a single queued scan or job if available.
    pub async fn poll_and_execute_once(&self) -> Result<Option<Uuid>, ScanWorkerError> {
        // 1. Try dequeueing from persistent/in-memory job queue
        if let Some(job) = self.job_queue.dequeue().await {
            let scan_id = job.scan_id;
            self.execute_job(job).await?;
            return Ok(Some(scan_id));
        }

        // 2. Poll repository for any Queued scans
        let apps = self.app_repo.list(None, None).await?;
        for app in apps {
            let scans_page = self.scan_repo.list_by_app(app.id, 1, 10).await?;
            if let Some(queued) = scans_page
                .items
                .into_iter()
                .find(|s| s.status == ScanStatus::Queued)
            {
                let scan_id = queued.id;
                self.execute_scan(scan_id).await?;
                return Ok(Some(scan_id));
            }
        }

        Ok(None)
    }

    /// Starts a background polling worker task that continuously consumes queued jobs until stopped.
    pub fn start_background_worker(
        self: Arc<Self>,
        poll_interval: Duration,
        mut stop_rx: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            tracing::info!("Scan worker background polling task started");
            loop {
                if *stop_rx.borrow() {
                    tracing::info!("Scan worker background polling task stopping");
                    break;
                }

                match self.poll_and_execute_once().await {
                    Ok(Some(scan_id)) => {
                        tracing::debug!(scan_id = %scan_id, "Completed scan from polling loop");
                    }
                    Ok(None) => {
                        // Queue empty, wait for next tick or stop signal
                        tokio::select! {
                            _ = tokio::time::sleep(poll_interval) => {}
                            _ = stop_rx.changed() => {
                                if *stop_rx.borrow() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "Error in background scan polling loop");
                        tokio::select! {
                            _ = tokio::time::sleep(poll_interval) => {}
                            _ = stop_rx.changed() => {
                                if *stop_rx.borrow() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Starts recurring cron scheduler evaluator task that dispatches scans for due applications.
    pub fn start_cron_scheduler(
        self: Arc<Self>,
        check_interval: Duration,
        mut stop_rx: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        let evaluator = ScheduledScanEvaluator::new(self.app_repo.clone(), self.scan_repo.clone());

        tokio::spawn(async move {
            tracing::info!("Scan worker cron scheduler task started");
            loop {
                if *stop_rx.borrow() {
                    tracing::info!("Scan worker cron scheduler task stopping");
                    break;
                }

                let now = Utc::now();
                match evaluator.evaluate_due_scans(now).await {
                    Ok(triggered) => {
                        for (app_id, scan) in triggered {
                            tracing::info!(app_id = %app_id, scan_id = %scan.id, "Cron triggered scan; enqueueing");
                            let job = ScanJob {
                                scan_id: scan.id,
                                application_id: app_id,
                                target_url: scan.id.to_string(),
                                scan_type: scan.scan_type,
                                custom_headers: None,
                            };
                            self.job_queue.enqueue(job).await;
                        }
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "Error evaluating scheduled cron scans");
                    }
                }

                tokio::select! {
                    _ = tokio::time::sleep(check_interval) => {}
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    }
}
