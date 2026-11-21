//! Tier 4: Real-World Scenario 4 - CI/CD Pipeline Scan Trigger & Quality Gate

use axum::http::StatusCode;
use infra::traits::UserRepository;
use serde_json::json;

use crate::common::*;
use infra::traits::ZapAlert;

#[tokio::test]
async fn test_tier4_scenario_cicd_pipeline_quality_gate() {
    let harness = IntegratedHarness::new().await;
    let admin_user = harness.user_repo.find_by_email("admin@kds.local").await.unwrap().unwrap();
    let cicd_api_key = harness.create_api_key(admin_user.id, "GitHub Actions Runner Key").await;

    // 1. CI/CD Pipeline creates application
    let app_req = json!({
        "name": "Microservice Checkout",
        "base_url": "https://checkout.staging.internal",
        "environment": "staging",
        "criticality": "high",
        "include_regexes": ["https://checkout.staging.internal/.*"],
        "exclude_regexes": [],
        "is_authorized": true
    });
    let (s_app, b_app) = harness.client.post_json_api_key("/api/v1/apps", app_req, &cicd_api_key).await;
    assert_eq!(s_app, StatusCode::CREATED);
    let app: ApplicationResponse = serde_json::from_slice(&b_app).unwrap();

    // 2. Set up scanner findings (1 High finding)
    let alert = ZapAlert {
        id: "301".to_string(),
        plugin_id: "40018".to_string(),
        alert: "SQL Injection".to_string(),
        name: Some("SQL Injection".to_string()),
        risk: "High".to_string(),
        confidence: "High".to_string(),
        url: "https://checkout.staging.internal/cart".to_string(),
        param: Some("item_id".to_string()),
        attack: Some("1'".to_string()),
        evidence: Some("Syntax error".to_string()),
        description: "SQLi".to_string(),
        solution: "Sanitize".to_string(),
        reference: None,
        cweid: Some("89".to_string()),
        wascid: None,
        method: Some("POST".to_string()),
        request_header: None,
        response_header: None,
    };
    harness.mock_zap.set_mock_alerts(vec![alert]).await;

    // 3. Pipeline triggers security scan
    let scan_req = json!({ "scan_type": "full_active" });
    let (s_scan, b_scan) = harness.client.post_json_api_key(&format!("/api/v1/apps/{}/scans", app.id), scan_req, &cicd_api_key).await;
    assert_eq!(s_scan, StatusCode::ACCEPTED);
    let scan: ScanResponse = serde_json::from_slice(&b_scan).unwrap();

    // 4. Background worker executes scan
    let executed = harness.scan_engine.poll_and_execute_once().await.unwrap();
    assert_eq!(executed, Some(scan.id));

    // 5. CI/CD Pipeline polls scan status
    let (s_poll, b_poll) = harness.client.get_api_key(&format!("/api/v1/scans/{}", scan.id), &cicd_api_key).await;
    assert_eq!(s_poll, StatusCode::OK);
    let completed: ScanResponse = serde_json::from_slice(&b_poll).unwrap();
    assert_eq!(completed.status, ScanStatus::Completed);

    // 6. CI/CD Quality Gate evaluation:
    // Policy: Block pipeline if Critical > 0 or High > 0
    let gate_passed = completed.severity_counts.critical == 0 && completed.severity_counts.high == 0;
    assert!(!gate_passed, "Quality gate should fail due to High SQLi finding");
    assert_eq!(completed.severity_counts.high, 1);
}
