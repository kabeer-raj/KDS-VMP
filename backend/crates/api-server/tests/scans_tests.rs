mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;
use shared_types::{
    AppCriticality, AppEnvironment, CreateApplicationRequest, ScanComparisonResponse,
    ScanResponse, ScanStatus, ScanType,
};
use uuid::Uuid;

#[tokio::test]
async fn test_scans_lifecycle_and_endpoints() {
    let harness = TestHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let seceng_tok = harness.seceng_token().await;

    // 1. Create target application
    let app_req = CreateApplicationRequest {
        name: "Scan Target App".to_string(),
        description: Some("Target for testing scans".to_string()),
        base_url: "https://scantest.internal".to_string(),
        environment: AppEnvironment::Staging,
        criticality: AppCriticality::High,
        team_name: Some("AppSec".to_string()),
        include_regexes: vec!["^https://scantest\\.internal/.*".to_string()],
        exclude_regexes: vec![],
        cron_schedule: None,
        is_authorized: true,
    };
    let app = harness
        .state
        .app_repo
        .create(&app_req, None)
        .await
        .unwrap();

    // 2. Trigger scan via /api/v1/apps/:id/scans
    let scan_payload = json!({
        "scan_type": "full_active",
        "max_duration_minutes": 30,
        "custom_headers": { "X-Scan-Test": "1" }
    });

    let (status, body) = harness
        .post_json_auth(
            &format!("/api/v1/apps/{}/scans", app.id),
            scan_payload.clone(),
            &seceng_tok,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let scan1: ScanResponse = parse_json(&body);
    assert_eq!(scan1.application_id, app.id);
    assert_eq!(scan1.scan_type, ScanType::FullActive);
    assert_eq!(scan1.status, ScanStatus::Queued);

    // 3. Triggering another scan while one is active -> 400 SCAN_ALREADY_IN_PROGRESS
    let (status, body) = harness
        .post_json_auth(
            &format!("/api/v1/apps/{}/scans", app.id),
            scan_payload.clone(),
            &seceng_tok,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "SCAN_ALREADY_IN_PROGRESS");

    // 4. Get scan by ID
    let (status, body) = harness
        .get_auth(&format!("/api/v1/scans/{}", scan1.id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let fetched_scan: ScanResponse = parse_json(&body);
    assert_eq!(fetched_scan.id, scan1.id);

    // 5. Cancel scan
    let (status, body) = harness
        .post_json_auth(
            &format!("/api/v1/scans/{}/cancel", scan1.id),
            json!({}),
            &admin_tok,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let cancelled: ScanResponse = parse_json(&body);
    assert_eq!(cancelled.status, ScanStatus::Cancelled);

    // 6. Trigger a second scan via /api/v1/scans global route
    let global_scan_payload = json!({
        "application_id": app.id,
        "scan_type": "baseline_passive"
    });
    let (status, body) = harness
        .post_json_auth("/api/v1/scans", global_scan_payload, &admin_tok)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let scan2: ScanResponse = parse_json(&body);
    assert_eq!(scan2.scan_type, ScanType::BaselinePassive);

    // Mark scan2 as completed with some metrics
    harness
        .state
        .scan_repo
        .update_status(scan2.id, ScanStatus::Completed, None)
        .await
        .unwrap();

    // 7. List scans for app
    let (status, body) = harness
        .get_auth(&format!("/api/v1/apps/{}/scans", app.id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let scans: Vec<ScanResponse> = parse_json(&body);
    assert_eq!(scans.len(), 2);

    // 8. Compare scans (diff)
    let (status, body) = harness
        .get_auth(
            &format!("/api/v1/scans/diff?base={}&target={}", scan1.id, scan2.id),
            &admin_tok,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let comp: ScanComparisonResponse = parse_json(&body);
    assert_eq!(comp.base_scan_id, scan1.id);
    assert_eq!(comp.target_scan_id, scan2.id);

    // Also test alias /api/v1/scans/compare
    let (status, _) = harness
        .get_auth(
            &format!("/api/v1/scans/compare?base={}&target={}", scan1.id, scan2.id),
            &admin_tok,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // 9. Get scan findings
    let (status, body) = harness
        .get_auth(&format!("/api/v1/scans/{}/findings", scan2.id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let findings: Vec<serde_json::Value> = parse_json(&body);
    assert!(findings.is_empty());

    // Also test alias /api/v1/scans/:id/report
    let (status, _body) = harness
        .get_auth(&format!("/api/v1/scans/{}/report", scan2.id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_scans_edge_cases() {
    let harness = TestHarness::new().await;
    let admin_tok = harness.admin_token().await;

    // 1. Missing target scan
    let fake_id = Uuid::new_v4();
    let (status, body) = harness
        .get_auth(&format!("/api/v1/scans/{}", fake_id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "SCAN_NOT_FOUND");

    // 2. Trigger scan on unauthorized app
    let (status, body) = harness
        .post_json_auth(
            &format!("/api/v1/apps/{}/scans", Uuid::new_v4()),
            json!({ "scan_type": "baseline_passive" }),
            &admin_tok,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "APPLICATION_NOT_FOUND");

    // 3. Diff missing parameters
    let (status, body) = harness.get_auth("/api/v1/scans/diff", &admin_tok).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_INPUT");
}
