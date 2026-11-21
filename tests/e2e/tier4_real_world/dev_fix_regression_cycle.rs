//! Tier 4: Real-World Scenario 2 & 3 - Developer Remediation Verification & Regression Cycle

use axum::http::StatusCode;
use serde_json::json;

use crate::common::*;
use infra::traits::ZapAlert;

#[tokio::test]
async fn test_tier4_scenario_dev_fix_and_regression_cycle() {
    let harness = IntegratedHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let dev_tok = harness.dev_token().await;
    let app = harness.seed_application("Customer Portal", "https://portal.acme.corp", true).await;

    let xss_alert = ZapAlert {
        id: "201".to_string(),
        plugin_id: "40012".to_string(),
        alert: "DOM XSS in user profile editor".to_string(),
        name: Some("DOM XSS".to_string()),
        risk: "Medium".to_string(),
        confidence: "High".to_string(),
        url: "https://portal.acme.corp/profile/edit".to_string(),
        param: Some("display_name".to_string()),
        attack: Some("<img src=x onerror=alert(1)>".to_string()),
        evidence: Some("Unsanitized innerHTML assignment".to_string()),
        description: "DOM-based cross-site scripting via unescaped display name".to_string(),
        solution: "Use textContent instead of innerHTML".to_string(),
        reference: Some("https://owasp.org/xss".to_string()),
        cweid: Some("79".to_string()),
        wascid: Some("8".to_string()),
        method: Some("GET".to_string()),
        request_header: None,
        response_header: None,
    };

    // -------------------------------------------------------------------------
    // Phase 1: Baseline Scan 1 discovers XSS
    // -------------------------------------------------------------------------
    harness.mock_zap.set_mock_alerts(vec![xss_alert.clone()]).await;

    let (s_t1, b_t1) = harness.client.post_json_auth(&format!("/api/v1/apps/{}/scans", app.id), json!({"scan_type": "full_active"}), &admin_tok).await;
    assert_eq!(s_t1, StatusCode::ACCEPTED);
    let scan1: ScanResponse = serde_json::from_slice(&b_t1).unwrap();

    let exec1 = harness.scan_engine.poll_and_execute_once().await.unwrap();
    assert_eq!(exec1, Some(scan1.id));

    let (_, b_f1) = harness.client.get_auth(&format!("/api/v1/vulns?app_id={}", app.id), &dev_tok).await;
    let findings1: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&b_f1).unwrap();
    assert_eq!(findings1.total, 1);
    let vuln_id = findings1.items[0].id;
    assert_eq!(findings1.items[0].status, RemediationStatus::Open);

    // -------------------------------------------------------------------------
    // Phase 2: Developer fixes vulnerability and resolves ticket
    // -------------------------------------------------------------------------
    let resolve_payload = json!({
        "status": "resolved",
        "comment": "Replaced innerHTML with DOMPurify sanitization in PR #314"
    });
    let (s_res, _) = harness.client.patch_json_auth(&format!("/api/v1/vulns/{}", vuln_id), resolve_payload, &dev_tok).await;
    assert_eq!(s_res, StatusCode::OK);

    // -------------------------------------------------------------------------
    // Phase 3: Scan 2 re-detects the bug -> Diff engine flags Regression!
    // -------------------------------------------------------------------------
    harness.mock_zap.set_mock_alerts(vec![xss_alert.clone()]).await;

    let (s_t2, b_t2) = harness.client.post_json_auth(&format!("/api/v1/apps/{}/scans", app.id), json!({"scan_type": "full_active"}), &admin_tok).await;
    assert_eq!(s_t2, StatusCode::ACCEPTED);
    let scan2: ScanResponse = serde_json::from_slice(&b_t2).unwrap();

    let exec2 = harness.scan_engine.poll_and_execute_once().await.unwrap();
    assert_eq!(exec2, Some(scan2.id));

    // Verify finding transitioned to Regressed
    let (_, b_v2) = harness.client.get_auth(&format!("/api/v1/vulns/{}", vuln_id), &dev_tok).await;
    let vuln_v2: VulnerabilityDetail = serde_json::from_slice(&b_v2).unwrap();
    assert_eq!(vuln_v2.summary.status, RemediationStatus::Regressed);

    // -------------------------------------------------------------------------
    // Phase 4: Developer properly fixes bug and Scan 3 verifies fix (Alert absent)
    // -------------------------------------------------------------------------
    harness.mock_zap.set_mock_alerts(vec![]).await; // Clean scan

    let (s_t3, b_t3) = harness.client.post_json_auth(&format!("/api/v1/apps/{}/scans", app.id), json!({"scan_type": "full_active"}), &admin_tok).await;
    assert_eq!(s_t3, StatusCode::ACCEPTED);
    let scan3: ScanResponse = serde_json::from_slice(&b_t3).unwrap();

    let exec3 = harness.scan_engine.poll_and_execute_once().await.unwrap();
    assert_eq!(exec3, Some(scan3.id));

    // Verify finding transitioned to VerifiedFixed
    let (_, b_v3) = harness.client.get_auth(&format!("/api/v1/vulns/{}", vuln_id), &dev_tok).await;
    let vuln_v3: VulnerabilityDetail = serde_json::from_slice(&b_v3).unwrap();
    assert_eq!(vuln_v3.summary.status, RemediationStatus::VerifiedFixed);
    assert!(vuln_v3.resolved_at.is_some());

    // Verify remediation history captures all lifecycle transitions
    let (_, b_hist) = harness.client.get_auth(&format!("/api/v1/vulns/{}/history", vuln_id), &dev_tok).await;
    let history: Vec<RemediationAuditLogResponse> = serde_json::from_slice(&b_hist).unwrap();
    assert!(history.len() >= 4);
}
