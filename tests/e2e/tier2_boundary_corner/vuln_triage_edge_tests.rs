//! Tier 2: Boundary & Corner Cases - Vulnerability Triage & Reports Edge Cases

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::*;

#[tokio::test]
async fn test_tier2_vuln_unauthenticated_requests_return_401() {
    let harness = IntegratedHarness::new().await;

    let (s1, _) = harness.client.get("/api/v1/vulns").await;
    assert_eq!(s1, StatusCode::UNAUTHORIZED);

    let (s2, _) = harness.client.get("/api/v1/vulns/00000000-0000-0000-0000-000000000000").await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);

    let (s3, _) = harness.client.get("/api/v1/reports/scans/00000000-0000-0000-0000-000000000000/pdf").await;
    assert_eq!(s3, StatusCode::UNAUTHORIZED);

    let (s4, _) = harness.client.get("/api/v1/dashboard/summary").await;
    assert_eq!(s4, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tier2_vuln_get_malformed_uuid_404() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;

    let (status, body) = harness.client.get_auth("/api/v1/vulns/not-a-valid-uuid", &token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "VULNERABILITY_NOT_FOUND");
}

#[tokio::test]
async fn test_tier2_vuln_get_nonexistent_uuid_404() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let non_existent = Uuid::new_v4();

    let uri = format!("/api/v1/vulns/{}", non_existent);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "VULNERABILITY_NOT_FOUND");
}

#[tokio::test]
async fn test_tier2_vuln_triage_auditor_role_forbidden_403() {
    let harness = IntegratedHarness::new().await;
    let auditor_token = harness.auditor_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Auditor Triage Attempt", SeverityLevel::High, None).await;

    let patch_payload = json!({
        "status": "in_progress"
    });

    let uri = format!("/api/v1/vulns/{}", vuln.summary.id);
    let (status, body) = harness.client.patch_json_auth(&uri, patch_payload, &auditor_token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn test_tier2_vuln_add_comment_auditor_role_forbidden_403() {
    let harness = IntegratedHarness::new().await;
    let auditor_token = harness.auditor_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Auditor Comment Attempt", SeverityLevel::High, None).await;

    let payload = json!({
        "comment": "Auditor note"
    });

    let uri = format!("/api/v1/vulns/{}/comments", vuln.summary.id);
    let (status, body) = harness.client.post_json_auth(&uri, payload, &auditor_token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn test_tier2_vuln_bulk_update_auditor_role_forbidden_403() {
    let harness = IntegratedHarness::new().await;
    let auditor_token = harness.auditor_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Auditor Bulk Attempt", SeverityLevel::High, None).await;

    let payload = json!({
        "vuln_ids": [vuln.summary.id],
        "status": "resolved"
    });

    let (status, body) = harness.client.post_json_auth("/api/v1/vulns/bulk-update", payload, &auditor_token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn test_tier2_vuln_empty_comment_rejected_400() {
    let harness = IntegratedHarness::new().await;
    let dev_token = harness.dev_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Empty Comment Test", SeverityLevel::High, None).await;

    let payload = json!({
        "comment": "   "
    });

    let uri = format!("/api/v1/vulns/{}/comments", vuln.summary.id);
    let (status, body) = harness.client.post_json_auth(&uri, payload, &dev_token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn test_tier2_vuln_triage_nonexistent_vuln_404() {
    let harness = IntegratedHarness::new().await;
    let dev_token = harness.dev_token().await;
    let non_existent = Uuid::new_v4();

    let patch_payload = json!({
        "status": "in_progress"
    });

    let uri = format!("/api/v1/vulns/{}", non_existent);
    let (status, body) = harness.client.patch_json_auth(&uri, patch_payload, &dev_token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "VULNERABILITY_NOT_FOUND");
}

#[tokio::test]
async fn test_tier2_vuln_history_nonexistent_vuln_404() {
    let harness = IntegratedHarness::new().await;
    let dev_token = harness.dev_token().await;
    let non_existent = Uuid::new_v4();

    let uri = format!("/api/v1/vulns/{}/history", non_existent);
    let (status, body) = harness.client.get_auth(&uri, &dev_token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "VULNERABILITY_NOT_FOUND");
}

#[tokio::test]
async fn test_tier2_vuln_bulk_update_nonexistent_ids_returns_zero() {
    let harness = IntegratedHarness::new().await;
    let dev_token = harness.dev_token().await;

    let payload = json!({
        "vuln_ids": [Uuid::new_v4(), Uuid::new_v4()],
        "status": "resolved"
    });

    let (status, body) = harness.client.post_json_auth("/api/v1/vulns/bulk-update", payload, &dev_token).await;
    assert_eq!(status, StatusCode::OK);
    let res: BulkUpdateResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.updated_count, 0);
}

#[tokio::test]
async fn test_tier2_report_pdf_nonexistent_scan_404() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let non_existent = Uuid::new_v4();

    let uri = format!("/api/v1/reports/scans/{}/pdf", non_existent);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn test_tier2_report_pdf_nonexistent_app_404() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let non_existent = Uuid::new_v4();

    let uri = format!("/api/v1/reports/apps/{}/pdf", non_existent);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error"]["code"], "APPLICATION_NOT_FOUND");
}
