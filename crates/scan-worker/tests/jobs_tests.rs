use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

use infra::memory::{InMemoryAppRepo, InMemoryPubSub, InMemoryScanRepo, InMemoryVulnRepo};
use infra::traits::{AppRepository, PubSubPort, ScanRepository, ZapClient};
use infra::zap::client::MockZapClient;
use scan_worker::engine::ScanWorkerEngine;
use scan_worker::error::ScanWorkerError;
use scan_worker::jobs::{execute_scan_by_id, execute_scan_job, run_scheduled_cron_evaluator};
use scan_worker::queue::ScanJob;
use shared_types::app::CreateApplicationRequest;
use shared_types::enums::{AppCriticality, AppEnvironment, ScanStatus, ScanType};
use shared_types::scan::TriggerScanRequest;

#[tokio::test]
async fn test_jobs_execute_scan_job_and_by_id() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo = Arc::new(InMemoryVulnRepo::new());
    let zap_client: Arc<dyn ZapClient> = Arc::new(MockZapClient::new());
    let pubsub: Arc<dyn PubSubPort> = Arc::new(InMemoryPubSub::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Jobs Test App".to_string(),
                description: None,
                base_url: "https://jobs.local".to_string(),
                environment: AppEnvironment::Production,
                criticality: AppCriticality::High,
                team_name: None,
                include_regexes: vec![],
                exclude_regexes: vec![],
                cron_schedule: None,
                is_authorized: true,
            },
            None,
        )
        .await
        .unwrap();

    let scan = scan_repo
        .create(
            app.id,
            None,
            &TriggerScanRequest {
                scan_type: ScanType::FullActive,
                max_duration_minutes: None,
                custom_headers: None,
            },
            None,
        )
        .await
        .unwrap();

    let engine = ScanWorkerEngine::new(
        app_repo,
        scan_repo.clone(),
        vuln_repo,
        zap_client,
        pubsub,
    );

    // Test execute_scan_by_id
    let res = execute_scan_by_id(&engine, scan.id).await.unwrap();
    assert_eq!(res.status, ScanStatus::Completed);
    assert_eq!(res.progress_percent, 100);

    // Test non-existent scan ID
    let missing_scan_id = Uuid::new_v4();
    let err = execute_scan_by_id(&engine, missing_scan_id).await;
    assert!(matches!(err, Err(ScanWorkerError::ScanNotFound(_))));

    // Test execute_scan_job
    let scan2 = scan_repo
        .create(
            app.id,
            None,
            &TriggerScanRequest {
                scan_type: ScanType::BaselinePassive,
                max_duration_minutes: None,
                custom_headers: None,
            },
            None,
        )
        .await
        .unwrap();

    let job = ScanJob {
        scan_id: scan2.id,
        application_id: app.id,
        target_url: app.base_url.clone(),
        scan_type: ScanType::BaselinePassive,
        custom_headers: None,
    };

    let res2 = execute_scan_job(&engine, &job).await.unwrap();
    assert_eq!(res2.status, ScanStatus::Completed);
}

#[tokio::test]
async fn test_jobs_run_scheduled_cron_evaluator() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo = Arc::new(InMemoryVulnRepo::new());
    let zap_client: Arc<dyn ZapClient> = Arc::new(MockZapClient::new());
    let pubsub: Arc<dyn PubSubPort> = Arc::new(InMemoryPubSub::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Scheduled Job App".to_string(),
                description: None,
                base_url: "https://sched.local".to_string(),
                environment: AppEnvironment::Staging,
                criticality: AppCriticality::Medium,
                team_name: None,
                include_regexes: vec![],
                exclude_regexes: vec![],
                cron_schedule: Some("0 0 * * *".to_string()),
                is_authorized: true,
            },
            None,
        )
        .await
        .unwrap();

    let engine = ScanWorkerEngine::new(
        app_repo,
        scan_repo.clone(),
        vuln_repo,
        zap_client,
        pubsub,
    );

    let scheduled_scans = run_scheduled_cron_evaluator(&engine, Utc::now()).await.unwrap();
    assert_eq!(scheduled_scans.len(), 1);

    // Verify it enqueued into engine's job_queue
    assert_eq!(engine.job_queue.len().await, 1);
    let job = engine.job_queue.dequeue().await.unwrap();
    assert_eq!(job.scan_id, scheduled_scans[0]);
    assert_eq!(job.application_id, app.id);
}
