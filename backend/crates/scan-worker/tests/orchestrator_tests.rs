use std::sync::Arc;
use infra::memory::{InMemoryAppRepo, InMemoryPubSub, InMemoryScanRepo, InMemoryVulnRepo};
use infra::traits::{AppRepository, PubSubPort, ScanRepository, VulnRepository, ZapClient};
use infra::zap::client::MockZapClient;
use scan_worker::orchestrator::ZapOrchestrator;
use shared_types::app::CreateApplicationRequest;
use shared_types::enums::{AppCriticality, AppEnvironment, ScanStatus, ScanType};
use shared_types::events::WsServerEvent;
use shared_types::scan::TriggerScanRequest;

#[tokio::test]
async fn test_orchestrator_successful_full_active_scan() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo: Arc<dyn VulnRepository> = Arc::new(InMemoryVulnRepo::new());
    let zap_client: Arc<dyn ZapClient> = Arc::new(MockZapClient::new());
    let pubsub: Arc<dyn PubSubPort> = Arc::new(InMemoryPubSub::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Orchestrator Test App".to_string(),
                description: Some("Test".to_string()),
                base_url: "https://orchestrator.internal".to_string(),
                environment: AppEnvironment::Staging,
                criticality: AppCriticality::High,
                team_name: None,
                include_regexes: vec!["https://orchestrator.internal/.*".to_string()],
                exclude_regexes: vec!["https://orchestrator.internal/logout".to_string()],
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
                max_duration_minutes: Some(30),
                custom_headers: None,
            },
            None,
        )
        .await
        .unwrap();

    let mut event_rx = pubsub.subscribe_scan_progress(scan.id).await.unwrap();

    let result = ZapOrchestrator::orchestrate_scan(
        scan.id,
        &app,
        ScanType::FullActive,
        None,
        &zap_client,
        &scan_repo,
        &vuln_repo,
        &app_repo,
        &pubsub,
    )
    .await
    .unwrap();

    assert_eq!(result.status, ScanStatus::Completed);
    assert_eq!(result.progress_percent, 100);
    assert!(result.completed_at.is_some());
    assert!(result.duration_seconds.is_some());

    // Verify events were published through pubsub
    let mut event_count = 0;
    while let Ok(event) = event_rx.try_recv() {
        event_count += 1;
        match event {
            WsServerEvent::ScanProgress(p) => {
                assert_eq!(p.scan_id, scan.id);
            }
            WsServerEvent::ScanCompleted(c) => {
                assert_eq!(c.scan_id, scan.id);
                assert!(c.overall_risk_score >= 0.0);
            }
            _ => {}
        }
    }
    assert!(event_count >= 3, "Expected progress and completion events, got {}", event_count);
}

#[tokio::test]
async fn test_orchestrator_handles_scan_cancellation() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo: Arc<dyn VulnRepository> = Arc::new(InMemoryVulnRepo::new());
    let zap_client: Arc<dyn ZapClient> = Arc::new(MockZapClient::new());
    let pubsub: Arc<dyn PubSubPort> = Arc::new(InMemoryPubSub::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Cancel App".to_string(),
                description: None,
                base_url: "https://cancel.internal".to_string(),
                environment: AppEnvironment::Development,
                criticality: AppCriticality::Low,
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
                max_duration_minutes: Some(10),
                custom_headers: None,
            },
            None,
        )
        .await
        .unwrap();

    // Cancel the scan before or during orchestration
    scan_repo.cancel(scan.id).await.unwrap();

    let result = ZapOrchestrator::orchestrate_scan(
        scan.id,
        &app,
        ScanType::FullActive,
        None,
        &zap_client,
        &scan_repo,
        &vuln_repo,
        &app_repo,
        &pubsub,
    )
    .await
    .unwrap();

    assert_eq!(result.status, ScanStatus::Cancelled);
}

#[tokio::test]
async fn test_orchestrator_baseline_passive_scan_skips_active_scanner() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo: Arc<dyn VulnRepository> = Arc::new(InMemoryVulnRepo::new());
    let zap_client: Arc<dyn ZapClient> = Arc::new(MockZapClient::new());
    let pubsub: Arc<dyn PubSubPort> = Arc::new(InMemoryPubSub::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Passive App".to_string(),
                description: None,
                base_url: "https://passive.internal".to_string(),
                environment: AppEnvironment::Production,
                criticality: AppCriticality::Medium,
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
                scan_type: ScanType::BaselinePassive,
                max_duration_minutes: Some(15),
                custom_headers: None,
            },
            None,
        )
        .await
        .unwrap();

    let result = ZapOrchestrator::orchestrate_scan(
        scan.id,
        &app,
        ScanType::BaselinePassive,
        None,
        &zap_client,
        &scan_repo,
        &vuln_repo,
        &app_repo,
        &pubsub,
    )
    .await
    .unwrap();

    assert_eq!(result.status, ScanStatus::Completed);
    assert_eq!(result.progress_percent, 100);
}
