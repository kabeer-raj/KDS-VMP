mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;
use shared_types::{
    BulkUpdateResponse, PaginatedResponse, RemediationAuditLogResponse, RemediationStatus,
    SeverityLevel, VulnerabilityDetail, VulnerabilitySummary,
};
use uuid::Uuid;

use infra::traits::FindingIngestionInput;

#[tokio::test]
async fn test_vulnerabilities_endpoints() {
    let harness = TestHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let dev_tok = harness.dev_token().await;

    let app_id = Uuid::new_v4();
    let scan_id = Uuid::new_v4();

    // Ingest test findings into vuln_repo
    let raw_findings = vec![
        FindingIngestionInput {
            zap_plugin_id: "40018".to_string(),
            title: "SQL Injection in /api/v1/users".to_string(),
            cwe_id: Some(89),
            wasc_id: Some(19),
            confidence: "High".to_string(),
            http_method: "GET".to_string(),
            affected_url: "https://example.com/api/v1/users?id=1".to_string(),
            affected_param: Some("id".to_string()),
            attack_payload: Some("' OR '1'='1".to_string()),
            evidence_snippet: Some("syntax error near SELECT".to_string()),
            description: "User input concatenated into SQL query".to_string(),
            solution: "Use parameterized queries".to_string(),
            reference_urls: vec!["https://owasp.org/sqli".to_string()],
            raw_request_header: None,
            raw_response_header: None,
            cvss_score: Some(9.8),
            severity: Some(SeverityLevel::Critical),
        },
        FindingIngestionInput {
            zap_plugin_id: "40012".to_string(),
            title: "Cross Site Scripting (Reflected)".to_string(),
            cwe_id: Some(79),
            wasc_id: Some(8),
            confidence: "Medium".to_string(),
            http_method: "POST".to_string(),
            affected_url: "https://example.com/feedback".to_string(),
            affected_param: Some("comment".to_string()),
            attack_payload: Some("<script>alert(1)</script>".to_string()),
            evidence_snippet: Some("<script>alert(1)</script>".to_string()),
            description: "Unescaped user input reflected into DOM".to_string(),
            solution: "Encode output in HTML body".to_string(),
            reference_urls: vec!["https://owasp.org/xss".to_string()],
            raw_request_header: None,
            raw_response_header: None,
            cvss_score: Some(6.1),
            severity: Some(SeverityLevel::Medium),
        },
    ];

    let _diff_res = harness
        .state
        .vuln_repo
        .upsert_findings(scan_id, app_id, &raw_findings, None)
        .await
        .unwrap();

    // 1. List vulnerabilities via /api/v1/vulnerabilities
    let (status, body) = harness
        .get_auth("/api/v1/vulnerabilities", &admin_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let page_resp: PaginatedResponse<VulnerabilitySummary> = parse_json(&body);
    assert_eq!(page_resp.total, 2);
    assert_eq!(page_resp.items.len(), 2);

    let vuln1 = &page_resp.items[0];
    let vuln2 = &page_resp.items[1];

    // 2. Filter by severity
    let (status, body) = harness
        .get_auth("/api/v1/vulns?severity=critical", &dev_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let filtered: PaginatedResponse<VulnerabilitySummary> = parse_json(&body);
    assert_eq!(filtered.total, 1);
    assert_eq!(filtered.items[0].severity, SeverityLevel::Critical);

    // 3. Get vulnerability details
    let (status, body) = harness
        .get_auth(&format!("/api/v1/vulns/{}", vuln1.id), &dev_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let detail: VulnerabilityDetail = parse_json(&body);
    assert_eq!(detail.summary.id, vuln1.id);
    assert!(detail.description.contains("SQL query") || detail.description.contains("DOM"));

    // 4. Patch vulnerability triage
    let (status, body) = harness
        .patch_json_auth(
            &format!("/api/v1/vulnerabilities/{}", vuln1.id),
            json!({
                "status": "in_progress",
                "severity": "high",
                "comment": "Working on parameterized query fix"
            }),
            &dev_tok,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let patched: VulnerabilityDetail = parse_json(&body);
    assert_eq!(patched.summary.status, RemediationStatus::InProgress);
    assert_eq!(patched.summary.severity, SeverityLevel::High);

    // 5. Add comment
    let (status, body) = harness
        .post_json_auth(
            &format!("/api/v1/vulns/{}/comments", vuln1.id),
            json!({ "comment": "PR created with fix" }),
            &dev_tok,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let comment_log: RemediationAuditLogResponse = parse_json(&body);
    assert_eq!(comment_log.comment, Some("PR created with fix".to_string()));

    // 6. Get audit history
    let (status, body) = harness
        .get_auth(&format!("/api/v1/vulns/{}/history", vuln1.id), &dev_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let history: Vec<RemediationAuditLogResponse> = parse_json(&body);
    assert!(!history.is_empty());

    // 7. Bulk update
    let (status, body) = harness
        .post_json_auth(
            "/api/v1/vulns/bulk-update",
            json!({
                "vuln_ids": [vuln1.id, vuln2.id],
                "status": "risk_accepted",
                "comment": "Bulk risk acceptance approved by SecOps"
            }),
            &admin_tok,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let bulk_resp: BulkUpdateResponse = parse_json(&body);
    assert_eq!(bulk_resp.updated_count, 2);
}
