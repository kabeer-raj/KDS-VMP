use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use infra::memory::{InMemoryAppRepo, InMemoryPubSub, InMemoryScanRepo, InMemoryVulnRepo};
use infra::traits::{AppRepository, PubSubPort, ScanRepository, ZapClient};
use infra::zap::client::MockZapClient;
use scan_worker::engine::ScanWorkerEngine;
use scan_worker::queue::{InMemoryScanJobQueue, ScanJob};
use shared_types::app::CreateApplicationRequest;
use shared_types::enums::{AppCriticality, AppEnvironment, ScanStatus, ScanType};
use shared_types::scan::TriggerScanRequest;

#[tokio::test]
async fn test_in_memory_job_queue_enqueue_dequeue() {
    let queue = InMemoryScanJobQueue::new();
    assert!(queue.is_empty().await);
    assert_eq!(queue.len().await, 0);

    let job = ScanJob {
        scan_id: uuid::Uuid::new_v4(),
        application_id: uuid::Uuid::new_v4(),
        target_url: "https://queue.local".to_string(),
        scan_type: ScanType::FullActive,
        custom_headers: None,
    };

    queue.enqueue(job.clone()).await;
    assert!(!queue.is_empty().await);
    assert_eq!(queue.len().await, 1);

    let popped = queue.dequeue().await;
    assert!(popped.is_some());
    assert_eq!(popped.unwrap().scan_id, job.scan_id);
    assert!(queue.is_empty().await);
}

#[tokio::test]
async fn test_engine_poll_and_execute_once() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo = Arc::new(InMemoryVulnRepo::new());
    let zap_client: Arc<dyn ZapClient> = Arc::new(MockZapClient::new());
    let pubsub: Arc<dyn PubSubPort> = Arc::new(InMemoryPubSub::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Engine App".to_string(),
                description: None,
                base_url: "https://engine.local".to_string(),
                environment: AppEnvironment::Staging,
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

    // Poll and execute the queued scan
    let executed_scan_id = engine.poll_and_execute_once().await.unwrap();
    assert_eq!(executed_scan_id, Some(scan.id));

    // Verify scan completed
    let finished = scan_repo.get_by_id(scan.id).await.unwrap().unwrap();
    assert_eq!(finished.status, ScanStatus::Completed);
    assert_eq!(finished.progress_percent, 100);

    // Second poll should find nothing
    let next = engine.poll_and_execute_once().await.unwrap();
    assert_eq!(next, None);
}

#[tokio::test]
async fn test_engine_background_worker_task_lifecycle() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo = Arc::new(InMemoryVulnRepo::new());
    let zap_client: Arc<dyn ZapClient> = Arc::new(MockZapClient::new());
    let pubsub: Arc<dyn PubSubPort> = Arc::new(InMemoryPubSub::new());

    let engine = Arc::new(ScanWorkerEngine::new(
        app_repo,
        scan_repo,
        vuln_repo,
        zap_client,
        pubsub,
    ));

    let (stop_tx, stop_rx) = watch::channel(false);
    let handle = engine.start_background_worker(Duration::from_millis(10), stop_rx);

    // Let it run briefly
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Signal stop
    let _ = stop_tx.send(true);
    let res = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(res.is_ok(), "Background worker must stop promptly when signalled");
}
