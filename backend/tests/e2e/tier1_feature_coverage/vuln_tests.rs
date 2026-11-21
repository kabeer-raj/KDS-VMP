//! Tier 1: Feature Coverage - Vulnerability Management & Triage Tests (F4, F40-F45)

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::*;

#[tokio::test]
async fn test_f40_list_vulns_empty() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;

    let (status, body) = harness.client.get_auth("/api/v1/vulns", &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.total, 0);
    assert_eq!(res.items.len(), 0);
    assert_eq!(res.page, 1);
}

#[tokio::test]
async fn test_f40_list_vulns_alias_route() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;

    let (status, body) = harness.client.get_auth("/api/v1/vulnerabilities", &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.total, 0);
}

#[tokio::test]
async fn test_f40_list_vulns_with_items() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan_id = Uuid::new_v4();

    let vuln1 = harness.seed_vulnerability(app.id, scan_id, "SQL Injection in /api/users", SeverityLevel::High, Some(89)).await;
    let _vuln2 = harness.seed_vulnerability(app.id, scan_id, "Cross-Site Scripting in /search", SeverityLevel::Medium, Some(79)).await;

    let (status, body) = harness.client.get_auth("/api/v1/vulns", &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.total, 2);
    assert_eq!(res.items.len(), 2);
    assert!(res.items.iter().any(|v| v.id == vuln1.summary.id));
}

#[tokio::test]
async fn test_f40_list_vulns_filter_by_app_id() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app1 = harness.seed_application("App 1", "https://app1.test", true).await;
    let app2 = harness.seed_application("App 2", "https://app2.test", true).await;

    let scan1 = Uuid::new_v4();
    let scan2 = Uuid::new_v4();
    let vuln1 = harness.seed_vulnerability(app1.id, scan1, "SQLi in App 1", SeverityLevel::High, Some(89)).await;
    let _vuln2 = harness.seed_vulnerability(app2.id, scan2, "SQLi in App 2", SeverityLevel::High, Some(89)).await;

    let uri = format!("/api/v1/vulns?app_id={}", app1.id);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.total, 1);
    assert_eq!(res.items[0].id, vuln1.summary.id);
}

#[tokio::test]
async fn test_f40_list_vulns_filter_by_severity() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let _v_crit = harness.seed_vulnerability(app.id, scan, "Critical RCE", SeverityLevel::Critical, None).await;
    let v_high = harness.seed_vulnerability(app.id, scan, "High SQLi", SeverityLevel::High, Some(89)).await;

    let (status, body) = harness.client.get_auth("/api/v1/vulns?severity=high", &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.total, 1);
    assert_eq!(res.items[0].id, v_high.summary.id);
    assert_eq!(res.items[0].severity, SeverityLevel::High);
}

#[tokio::test]
async fn test_f40_list_vulns_filter_by_status() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let v1 = harness.seed_vulnerability(app.id, scan, "Open Vuln", SeverityLevel::High, None).await;

    let (status, body) = harness.client.get_auth("/api/v1/vulns?status=open", &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.total, 1);
    assert_eq!(res.items[0].id, v1.summary.id);
}

#[tokio::test]
async fn test_f40_list_vulns_filter_by_search_query() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let _v1 = harness.seed_vulnerability(app.id, scan, "Cross-Site Scripting", SeverityLevel::Medium, Some(79)).await;
    let v2 = harness.seed_vulnerability(app.id, scan, "Remote Code Execution", SeverityLevel::Critical, Some(94)).await;

    let (status, body) = harness.client.get_auth("/api/v1/vulns?search=Remote", &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.total, 1);
    assert_eq!(res.items[0].id, v2.summary.id);
}

#[tokio::test]
async fn test_f40_list_vulns_pagination() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    for i in 1..=5 {
        let title = format!("Vulnerability #{i}");
        harness.seed_vulnerability(app.id, scan, &title, SeverityLevel::Low, None).await;
    }

    let (status, body) = harness.client.get_auth("/api/v1/vulns?page=1&per_page=2", &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.total, 5);
    assert_eq!(res.per_page, 2);
    assert_eq!(res.page, 1);
    assert_eq!(res.items.len(), 2);
    assert_eq!(res.total_pages, 3);
}

#[tokio::test]
async fn test_f41_get_vuln_detail_by_id_200() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Detailed SQLi Finding", SeverityLevel::High, Some(89)).await;

    let uri = format!("/api/v1/vulns/{}", vuln.summary.id);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::OK);

    let detail: VulnerabilityDetail = serde_json::from_slice(&body).unwrap();
    assert_eq!(detail.summary.id, vuln.summary.id);
    assert_eq!(detail.summary.title, "Detailed SQLi Finding");
    assert_eq!(detail.summary.cwe_id, Some(89));
    assert!(detail.latest_evidence.is_some());
}

#[tokio::test]
async fn test_f41_get_vuln_detail_alias_route() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Alias Route Test", SeverityLevel::Medium, None).await;

    let uri = format!("/api/v1/vulnerabilities/{}", vuln.summary.id);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::OK);

    let detail: VulnerabilityDetail = serde_json::from_slice(&body).unwrap();
    assert_eq!(detail.summary.id, vuln.summary.id);
}

#[tokio::test]
async fn test_f42_patch_vuln_status_to_in_progress() {
    let harness = IntegratedHarness::new().await;
    let token = harness.dev_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Triage Status Test", SeverityLevel::High, None).await;

    let patch_payload = json!({
        "status": "in_progress",
        "comment": "Developer investigating root cause"
    });

    let uri = format!("/api/v1/vulns/{}", vuln.summary.id);
    let (status, body) = harness.client.patch_json_auth(&uri, patch_payload, &token).await;
    assert_eq!(status, StatusCode::OK);

    let updated: VulnerabilityDetail = serde_json::from_slice(&body).unwrap();
    assert_eq!(updated.summary.status, RemediationStatus::InProgress);
}

#[tokio::test]
async fn test_f42_patch_vuln_status_to_resolved() {
    let harness = IntegratedHarness::new().await;
    let token = harness.dev_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Resolve Test", SeverityLevel::Medium, None).await;

    let patch_payload = json!({
        "status": "resolved",
        "comment": "Sanitized inputs with prepared statements"
    });

    let uri = format!("/api/v1/vulns/{}", vuln.summary.id);
    let (status, body) = harness.client.patch_json_auth(&uri, patch_payload, &token).await;
    assert_eq!(status, StatusCode::OK);

    let updated: VulnerabilityDetail = serde_json::from_slice(&body).unwrap();
    assert_eq!(updated.summary.status, RemediationStatus::Resolved);
    assert!(updated.resolved_at.is_some());
}

#[tokio::test]
async fn test_f42_patch_vuln_severity_override() {
    let harness = IntegratedHarness::new().await;
    let token = harness.seceng_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Severity Override Test", SeverityLevel::Low, None).await;

    let patch_payload = json!({
        "severity": "critical",
        "comment": "Upgraded due to presence of sensitive customer records"
    });

    let uri = format!("/api/v1/vulns/{}", vuln.summary.id);
    let (status, body) = harness.client.patch_json_auth(&uri, patch_payload, &token).await;
    assert_eq!(status, StatusCode::OK);

    let updated: VulnerabilityDetail = serde_json::from_slice(&body).unwrap();
    assert_eq!(updated.summary.severity, SeverityLevel::Critical);
}

#[tokio::test]
async fn test_f42_patch_vuln_assignee() {
    let harness = IntegratedHarness::new().await;
    let token = harness.admin_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Assignee Test", SeverityLevel::High, None).await;
    let dev_id = Uuid::new_v4();

    let patch_payload = json!({
        "assigned_to": dev_id
    });

    let uri = format!("/api/v1/vulns/{}", vuln.summary.id);
    let (status, body) = harness.client.patch_json_auth(&uri, patch_payload, &token).await;
    assert_eq!(status, StatusCode::OK);

    let updated: VulnerabilityDetail = serde_json::from_slice(&body).unwrap();
    assert_eq!(updated.summary.assigned_to, Some(dev_id));
}

#[tokio::test]
async fn test_f43_bulk_update_status() {
    let harness = IntegratedHarness::new().await;
    let token = harness.dev_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let v1 = harness.seed_vulnerability(app.id, scan, "Bulk 1", SeverityLevel::Medium, None).await;
    let v2 = harness.seed_vulnerability(app.id, scan, "Bulk 2", SeverityLevel::Low, None).await;

    let bulk_payload = json!({
        "vuln_ids": [v1.summary.id, v2.summary.id],
        "status": "risk_accepted",
        "comment": "Compensating controls verified by CISO"
    });

    let (status, body) = harness.client.post_json_auth("/api/v1/vulns/bulk-update", bulk_payload, &token).await;
    assert_eq!(status, StatusCode::OK);

    let res: BulkUpdateResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.updated_count, 2);

    let (_, v1_body) = harness.client.get_auth(&format!("/api/v1/vulns/{}", v1.summary.id), &token).await;
    let v1_updated: VulnerabilityDetail = serde_json::from_slice(&v1_body).unwrap();
    assert_eq!(v1_updated.summary.status, RemediationStatus::RiskAccepted);
}

#[tokio::test]
async fn test_f44_get_vuln_remediation_history() {
    let harness = IntegratedHarness::new().await;
    let token = harness.dev_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "History Trail Test", SeverityLevel::High, None).await;

    let patch_payload = json!({
        "status": "in_progress",
        "comment": "Working on patch"
    });
    harness.client.patch_json_auth(&format!("/api/v1/vulns/{}", vuln.summary.id), patch_payload, &token).await;

    let uri = format!("/api/v1/vulns/{}/history", vuln.summary.id);
    let (status, body) = harness.client.get_auth(&uri, &token).await;
    assert_eq!(status, StatusCode::OK);

    let history: Vec<RemediationAuditLogResponse> = serde_json::from_slice(&body).unwrap();
    assert!(history.len() >= 2); // Initial creation log + status change log
    assert!(history.iter().any(|h| h.action_type == "status_change"));
}

#[tokio::test]
async fn test_f45_add_triage_comment_201() {
    let harness = IntegratedHarness::new().await;
    let token = harness.dev_token().await;
    let app = harness.seed_application("App 1", "https://app1.test", true).await;
    let scan = Uuid::new_v4();

    let vuln = harness.seed_vulnerability(app.id, scan, "Comment Test Finding", SeverityLevel::Medium, None).await;

    let comment_payload = json!({
        "comment": "Scheduled for deployment in Sprint 42"
    });

    let uri = format!("/api/v1/vulns/{}/comments", vuln.summary.id);
    let (status, body) = harness.client.post_json_auth(&uri, comment_payload, &token).await;
    assert_eq!(status, StatusCode::CREATED);

    let log: RemediationAuditLogResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(log.vulnerability_id, vuln.summary.id);
    assert_eq!(log.comment.as_deref(), Some("Scheduled for deployment in Sprint 42"));
    assert_eq!(log.action_type, "comment");
}

