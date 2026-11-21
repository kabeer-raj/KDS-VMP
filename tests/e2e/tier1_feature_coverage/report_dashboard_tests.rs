//! Tier 1: Feature Coverage - Executive Reports & Dashboard Tests (F46-F47)

use axum::http::StatusCode;
use uuid::Uuid;

use crate::common::*;

#[tokio::test]
async fn test_f46_dashboard_summary_empty_state() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;

    let (status, body) = harness.client.get_auth("/api/v1/dashboard/summary", &token).await;
    assert_eq!(status, StatusCode::OK);

    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["total_applications"], 0);
    assert_eq!(val["average_risk_score"], 0.0);
}

#[tokio::test]
async fn test_f46_dashboard_summary_with_applications_and_vulns() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("Production Bank", "https://bank.internal", true).await;
    let scan_id = Uuid::new_v4();

    let _vuln = harness.seed_vulnerability(app.id, scan_id, "SQLi in Login", SeverityLevel::High, Some(89)).await;

    let (status, body) = harness.client.get_auth("/api/v1/dashboard/summary", &token).await;
    assert_eq!(status, StatusCode::OK);

    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["total_applications"], 1);
    assert_eq!(val["total_vulnerabilities"], 1);
}

#[tokio::test]
async fn test_f47_scan_report_pdf_download() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("Report Test App", "https://report.test", true).await;

    // Trigger scan and complete it
    use shared_types::scan::TriggerScanRequest;
    use infra::traits::ScanRepository;
    let scan_req = TriggerScanRequest {
        scan_type: ScanType::FullActive,
        max_duration_minutes: Some(30),
        custom_headers: None,
    };
    let scan = harness.scan_repo.create(app.id, None, &scan_req, None).await.unwrap();

    let uri = format!("/api/v1/reports/scans/{}/pdf", scan.id);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.is_empty(), "PDF byte stream must not be empty");
    assert!(body.starts_with(b"%PDF"), "PDF byte stream must start with %PDF magic bytes");
}

#[tokio::test]
async fn test_f47_scan_report_pdf_alias_route() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("Report Test App", "https://report.test", true).await;

    use shared_types::scan::TriggerScanRequest;
    use infra::traits::ScanRepository;
    let scan_req = TriggerScanRequest {
        scan_type: ScanType::FullActive,
        max_duration_minutes: Some(30),
        custom_headers: None,
    };
    let scan = harness.scan_repo.create(app.id, None, &scan_req, None).await.unwrap();

    let uri = format!("/api/v1/reports/{}/pdf", scan.id);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with(b"%PDF"));
}

#[tokio::test]
async fn test_f47_scan_report_json_download() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("Report JSON App", "https://json.test", true).await;

    use shared_types::scan::TriggerScanRequest;
    use infra::traits::ScanRepository;
    let scan_req = TriggerScanRequest {
        scan_type: ScanType::FullActive,
        max_duration_minutes: Some(30),
        custom_headers: None,
    };
    let scan = harness.scan_repo.create(app.id, None, &scan_req, None).await.unwrap();

    let uri = format!("/api/v1/reports/{}/json", scan.id);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::OK);

    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["scan"]["id"], scan.id.to_string());
    assert_eq!(val["application"]["name"], "Report JSON App");
}

#[tokio::test]
async fn test_f47_app_posture_report_pdf_download() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("Posture App", "https://posture.test", true).await;

    let uri = format!("/api/v1/reports/apps/{}/pdf", app.id);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.is_empty());
    assert!(body.starts_with(b"%PDF"));
}

