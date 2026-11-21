use std::sync::Arc;
use chrono::{Duration, Utc};
use infra::memory::{InMemoryAppRepo, InMemoryScanRepo};
use infra::traits::{AppRepository, ScanRepository};
use scan_worker::scheduler::{cron::CronExpression, ScheduledScanEvaluator};
use shared_types::app::CreateApplicationRequest;
use shared_types::enums::{AppCriticality, AppEnvironment, ScanStatus, ScanType};
use shared_types::scan::TriggerScanRequest;

#[test]
fn test_cron_expression_parsing_valid_cases() {
    let valid = [
        "0 0 * * *",       // Midnight daily
        "0 2 * * 1",       // 2 AM on Mondays
        "*/15 * * * *",    // Every 15 minutes
        "1,15,30 * * * *", // Comma-separated minutes
        "0 9-17 * * 1-5",  // Working hours on weekdays
        "59 23 31 12 7",   // Edge boundaries (Sunday as 7)
        "0 0 1 1 0",       // Edge boundaries (Sunday as 0)
    ];

    for expr in valid {
        assert!(CronExpression::is_valid(expr), "Expression '{}' must be valid", expr);
        let parsed = CronExpression::parse(expr);
        assert!(parsed.is_ok());
    }
}

#[test]
fn test_cron_expression_parsing_invalid_cases_rejected() {
    let invalid = [
        "* * *",           // Only 3 fields
        "* * * *",         // Only 4 fields
        "* * * * * *",     // 6 fields
        "",                // Empty
        "   ",             // Whitespace only
        "60 * * * *",      // Minute out of bounds (60)
        "* 24 * * *",      // Hour out of bounds (24)
        "* * 0 * *",       // Day out of bounds (0)
        "* * 32 * *",      // Day out of bounds (32)
        "* * * 0 *",       // Month out of bounds (0)
        "* * * 13 *",      // Month out of bounds (13)
        "* * * * 8",       // Weekday out of bounds (8)
        "*/0 * * * *",     // Step 0
        "10-5 * * * *",    // Range inverted
        "abc * * * *",     // Non-numeric
    ];

    for expr in invalid {
        assert!(!CronExpression::is_valid(expr), "Expression '{}' must be rejected", expr);
        assert!(CronExpression::parse(expr).is_err());
    }
}

#[test]
fn test_cron_is_due_evaluation() {
    let cron = CronExpression::parse("0 0 * * *").unwrap();

    // Never scanned -> due immediately
    assert!(cron.is_due(None, Utc::now()));

    // Scanned 25 hours ago -> due
    let last_scanned = Utc::now() - Duration::hours(25);
    assert!(cron.is_due(Some(last_scanned), Utc::now()));

    // Scanned 1 minute ago -> not due
    let recent = Utc::now() - Duration::minutes(1);
    assert!(!cron.is_due(Some(recent), Utc::now()));
}

#[tokio::test]
async fn test_scheduled_evaluator_triggers_due_scan() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Cron Due App".to_string(),
                description: None,
                base_url: "https://cron.local".to_string(),
                environment: AppEnvironment::Production,
                criticality: AppCriticality::High,
                team_name: None,
                include_regexes: vec![],
                exclude_regexes: vec![],
                cron_schedule: Some("0 2 * * *".to_string()),
                is_authorized: true,
            },
            None,
        )
        .await
        .unwrap();

    let evaluator = ScheduledScanEvaluator::new(app_repo.clone(), scan_repo.clone());
    let triggered = evaluator.evaluate_due_scans(Utc::now()).await.unwrap();

    assert_eq!(triggered.len(), 1);
    assert_eq!(triggered[0].0, app.id);
    assert_eq!(triggered[0].1.status, ScanStatus::Queued);
}

#[tokio::test]
async fn test_scheduled_evaluator_skips_unauthorized_app() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());

    app_repo
        .create(
            &CreateApplicationRequest {
                name: "Unauthorized Cron App".to_string(),
                description: None,
                base_url: "https://unauth.local".to_string(),
                environment: AppEnvironment::Production,
                criticality: AppCriticality::High,
                team_name: None,
                include_regexes: vec![],
                exclude_regexes: vec![],
                cron_schedule: Some("0 2 * * *".to_string()),
                is_authorized: false, // Unauthorized!
            },
            None,
        )
        .await
        .unwrap();

    let evaluator = ScheduledScanEvaluator::new(app_repo.clone(), scan_repo.clone());
    let triggered = evaluator.evaluate_due_scans(Utc::now()).await.unwrap();

    assert!(triggered.is_empty(), "Unauthorized apps must never be scheduled");
}

#[tokio::test]
async fn test_scheduled_evaluator_skips_app_with_active_scan() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Active Scan App".to_string(),
                description: None,
                base_url: "https://active.local".to_string(),
                environment: AppEnvironment::Staging,
                criticality: AppCriticality::Medium,
                team_name: None,
                include_regexes: vec![],
                exclude_regexes: vec![],
                cron_schedule: Some("0 2 * * *".to_string()),
                is_authorized: true,
            },
            None,
        )
        .await
        .unwrap();

    // Insert an active running scan for this app
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

    scan_repo.update_status(scan.id, ScanStatus::ActiveScanning, None).await.unwrap();

    let evaluator = ScheduledScanEvaluator::new(app_repo.clone(), scan_repo.clone());
    let triggered = evaluator.evaluate_due_scans(Utc::now()).await.unwrap();

    assert!(triggered.is_empty(), "Apps with active scans must not be triggered again");
}
