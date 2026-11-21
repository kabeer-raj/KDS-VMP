mod common;
use common::*;

use axum::http::StatusCode;
use shared_types::{
    AppCriticality, AppEnvironment, CreateApplicationRequest, TriggerScanRequest,
};
use uuid::Uuid;

#[tokio::test]
async fn test_ws_endpoints() {
    let harness = TestHarness::new().await;
    let admin_tok = harness.admin_token().await;

    // 1. Create app and scan
    let app = harness
        .state
        .app_repo
        .create(
            &CreateApplicationRequest {
                name: "WS Test App".to_string(),
                description: None,
                base_url: "https://wstest.internal".to_string(),
                environment: AppEnvironment::Staging,
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

    let scan = harness
        .state
        .scan_repo
        .create(
            app.id,
            None,
            &TriggerScanRequest {
                scan_type: shared_types::ScanType::FullActive,
                max_duration_minutes: None,
                custom_headers: None,
            },
            None,
        )
        .await
        .unwrap();

    // 2. Missing token rejected
    let (status, body) = harness
        .get(&format!("/ws/scans/{}/progress", scan.id))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "UNAUTHORIZED");

    // 3. Nonexistent scan rejected
    let fake_scan_id = Uuid::new_v4();
    let (status, body) = harness
        .get(&format!(
            "/ws/scans/{}/progress?token={}",
            fake_scan_id, admin_tok
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "SCAN_NOT_FOUND");

    // 4. Valid scan handshake accepted
    let (status, body) = harness
        .get(&format!(
            "/ws/scans/{}/progress?token={}",
            scan.id, admin_tok
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["status"], "ws_handshake_accepted");
    assert_eq!(val["scan_id"], scan.id.to_string());

    // 5. Test alias /ws/v1/scans/:id
    let (status, body) = harness
        .get(&format!("/ws/v1/scans/{}?token={}", scan.id, admin_tok))
        .await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["status"], "ws_handshake_accepted");

    // 6. Notifications endpoint
    let (status, body) = harness
        .get(&format!("/ws/v1/notifications?token={}", admin_tok))
        .await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["status"], "ws_notifications_accepted");
}
