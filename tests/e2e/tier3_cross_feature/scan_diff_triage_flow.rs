//! Tier 3: Cross-Feature Combinations - Scan Diffing & Finding Triage Lifecycle Flow

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::*;
use infra::traits::{FindingIngestionInput, VulnRepository};

#[tokio::test]
async fn test_tier3_scan_diff_auto_verify_and_regression_flow() {
    let harness = IntegratedHarness::new().await;
    let dev_tok = harness.dev_token().await;
    let app = harness.seed_application("Lifecycle App", "https://lifecycle.internal", true).await;

    let scan1_id = Uuid::new_v4();
    let scan2_id = Uuid::new_v4();
    let scan3_id = Uuid::new_v4();

    // -------------------------------------------------------------------------
    // Scan 1: Discover SQLi & XSS
    // -------------------------------------------------------------------------
    let sqli_alert = FindingIngestionInput {
        zap_plugin_id: "40018".to_string(),
        title: "SQL Injection in /api/data".to_string(),
        cwe_id: Some(89),
        wasc_id: Some(19),
        confidence: "High".to_string(),
        http_method: "GET".to_string(),
        affected_url: "https://lifecycle.internal/api/data".to_string(),
        affected_param: Some("id".to_string()),
        attack_payload: Some("' OR '1'='1".to_string()),
        evidence_snippet: Some("SQL error".to_string()),
        description: "SQL Injection".to_string(),
        solution: "Use parameters".to_string(),
        reference_urls: vec![],
        raw_request_header: None,
        raw_response_header: None,
        cvss_score: Some(8.5),
        severity: Some(SeverityLevel::High),
    };

    let xss_alert = FindingIngestionInput {
        zap_plugin_id: "40012".to_string(),
        title: "Reflected XSS in /search".to_string(),
        cwe_id: Some(79),
        wasc_id: Some(8),
        confidence: "Medium".to_string(),
        http_method: "GET".to_string(),
        affected_url: "https://lifecycle.internal/search".to_string(),
        affected_param: Some("q".to_string()),
        attack_payload: Some("<script>1</script>".to_string()),
        evidence_snippet: Some("<script>1</script>".to_string()),
        description: "XSS".to_string(),
        solution: "Encode output".to_string(),
        reference_urls: vec![],
        raw_request_header: None,
        raw_response_header: None,
        cvss_score: Some(6.1),
        severity: Some(SeverityLevel::Medium),
    };

    let diff1 = harness.vuln_repo.upsert_findings(scan1_id, app.id, &[sqli_alert.clone(), xss_alert.clone()], None).await.unwrap();
    assert_eq!(diff1.summary.new_count, 2);
    assert_eq!(diff1.summary.fixed_count, 0);

    // Retrieve the findings via REST API
    let (s1, b1) = harness.client.get_auth("/api/v1/vulns", &dev_tok).await;
    assert_eq!(s1, StatusCode::OK);
    let list1: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&b1).unwrap();
    assert_eq!(list1.total, 2);

    let sqli_vuln = list1.items.iter().find(|v| v.cwe_id == Some(89)).unwrap();
    assert_eq!(sqli_vuln.status, RemediationStatus::Open);

    // -------------------------------------------------------------------------
    // Step 2: Developer fixes SQLi and triages as Resolved
    // -------------------------------------------------------------------------
    let patch_payload = json!({
        "status": "resolved",
        "comment": "Fixed using prepared statements in commit ab12cd3"
    });
    let patch_uri = format!("/api/v1/vulns/{}", sqli_vuln.id);
    let (s_patch, _) = harness.client.patch_json_auth(&patch_uri, patch_payload, &dev_tok).await;
    assert_eq!(s_patch, StatusCode::OK);

    // -------------------------------------------------------------------------
    // Step 3: Scan 2 runs (SQLi is still present -> Diff engine detects Regression!)
    // -------------------------------------------------------------------------
    let diff2 = harness.vuln_repo.upsert_findings(scan2_id, app.id, &[sqli_alert.clone(), xss_alert.clone()], Some(scan1_id)).await.unwrap();
    assert_eq!(diff2.summary.regressed_count, 1);
    assert_eq!(diff2.summary.persistent_count, 1);

    // Verify SQLi transitioned to Regressed
    let (s_get, b_get) = harness.client.get_auth(&format!("/api/v1/vulns/{}", sqli_vuln.id), &dev_tok).await;
    assert_eq!(s_get, StatusCode::OK);
    let sqli_after_scan2: VulnerabilityDetail = serde_json::from_slice(&b_get).unwrap();
    assert_eq!(sqli_after_scan2.summary.status, RemediationStatus::Regressed);

    // -------------------------------------------------------------------------
    // Step 4: Scan 3 runs (SQLi is now genuinely fixed and absent, only XSS remains)
    // -------------------------------------------------------------------------
    let diff3 = harness.vuln_repo.upsert_findings(scan3_id, app.id, &[xss_alert.clone()], Some(scan2_id)).await.unwrap();
    assert_eq!(diff3.summary.fixed_count, 1);

    // Verify SQLi status transitioned to VerifiedFixed
    let (_, b_regr) = harness.client.get_auth(&format!("/api/v1/vulns/{}", sqli_vuln.id), &dev_tok).await;
    let sqli_verified_fixed: VulnerabilityDetail = serde_json::from_slice(&b_regr).unwrap();
    assert_eq!(sqli_verified_fixed.summary.status, RemediationStatus::VerifiedFixed);

    // -------------------------------------------------------------------------
    // Step 5: Verify immutable remediation audit history captures full lifecycle
    // -------------------------------------------------------------------------
    let (_, b_hist) = harness.client.get_auth(&format!("/api/v1/vulns/{}/history", sqli_vuln.id), &dev_tok).await;
    let history: Vec<RemediationAuditLogResponse> = serde_json::from_slice(&b_hist).unwrap();
    assert!(history.len() >= 4);

    let statuses: Vec<Option<RemediationStatus>> = history.iter().map(|h| h.new_status).collect();
    assert!(statuses.contains(&Some(RemediationStatus::Regressed)));
    assert!(statuses.contains(&Some(RemediationStatus::VerifiedFixed)));
    assert!(statuses.contains(&Some(RemediationStatus::Resolved)));
}
