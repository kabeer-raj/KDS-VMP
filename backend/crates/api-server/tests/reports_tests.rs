mod common;
use common::*;

use axum::http::StatusCode;
use shared_types::{
    AppCriticality, AppEnvironment, CreateApplicationRequest, TriggerScanRequest,
};

#[tokio::test]
async fn test_reports_pdf_and_json() {
    let harness = TestHarness::new().await;
    let admin_tok = harness.admin_token().await;

    // 1. Create app
    let app = harness
        .state
        .app_repo
        .create(
            &CreateApplicationRequest {
                name: "Report App".to_string(),
                description: None,
                base_url: "https://reportapp.internal".to_string(),
                environment: AppEnvironment::Production,
                criticality: AppCriticality::Critical,
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

    // 2. Create scan
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

    // 3. GET /api/v1/reports/:id/pdf
    let (status, headers, body) = harness
        .request(
            axum::http::Method::GET,
            &format!("/api/v1/reports/{}/pdf", scan.id),
            Some(&admin_tok),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("content-type"), Some("application/pdf"));
    assert!(body.starts_with(b"%PDF-1.4"));

    // 4. GET /api/v1/reports/scans/:id/pdf
    let (status, headers, body) = harness
        .request(
            axum::http::Method::GET,
            &format!("/api/v1/reports/scans/{}/pdf", scan.id),
            Some(&admin_tok),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("content-type"), Some("application/pdf"));
    assert!(body.starts_with(b"%PDF-1.4"));

    // 5. GET /api/v1/reports/:id/json
    let (status, body) = harness
        .get_auth(&format!("/api/v1/reports/{}/json", scan.id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let json_val: serde_json::Value = parse_json(&body);
    assert_eq!(json_val["scan"]["id"], scan.id.to_string());
    assert_eq!(json_val["application"]["id"], app.id.to_string());

    // 6. GET /api/v1/reports/apps/:id/pdf
    let (status, headers, body) = harness
        .request(
            axum::http::Method::GET,
            &format!("/api/v1/reports/apps/{}/pdf", app.id),
            Some(&admin_tok),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("content-type"), Some("application/pdf"));
    assert!(body.starts_with(b"%PDF-1.4"));
}
