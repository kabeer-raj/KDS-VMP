//! Tier 4: Real-World Scenario 5 - RBAC & Multi-Role Isolation

use axum::http::StatusCode;
use serde_json::json;

use crate::common::*;

#[tokio::test]
async fn test_tier4_scenario_multi_role_and_tenant_isolation() {
    let harness = IntegratedHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let seceng_tok = harness.seceng_token().await;
    let dev_tok = harness.dev_token().await;
    let auditor_tok = harness.auditor_token().await;

    // 1. Create two distinct target applications
    let app1 = harness.seed_application("Tenant Alpha App", "https://alpha.internal", true).await;
    let app2 = harness.seed_application("Tenant Beta App", "https://beta.internal", true).await;

    // 2. Auditor Role Boundary: Read-only access permitted, mutations forbidden
    let (s_aud_read, _) = harness.client.get_auth("/api/v1/apps", &auditor_tok).await;
    assert_eq!(s_aud_read, StatusCode::OK);

    let (s_aud_mut, _) = harness.client.post_json_auth("/api/v1/apps", json!({
        "name": "Rogue App",
        "base_url": "https://rogue.internal",
        "is_authorized": true
    }), &auditor_tok).await;
    assert_eq!(s_aud_mut, StatusCode::FORBIDDEN);

    // 3. Developer Role Boundary: Cannot delete application
    let (s_dev_del, _) = harness.client.delete_auth(&format!("/api/v1/apps/{}", app1.id), &dev_tok).await;
    assert_eq!(s_dev_del, StatusCode::FORBIDDEN);

    // 4. Security Engineer Role: Can trigger scan and triage vulnerabilities
    let (s_sec_scan, b_sec_scan) = harness.client.post_json_auth(&format!("/api/v1/apps/{}/scans", app1.id), json!({"scan_type": "baseline_passive"}), &seceng_tok).await;
    assert_eq!(s_sec_scan, StatusCode::ACCEPTED);
    let scan1: ScanResponse = serde_json::from_slice(&b_sec_scan).unwrap();

    let (s_sec_scan2, b_sec_scan2) = harness.client.post_json_auth(&format!("/api/v1/apps/{}/scans", app2.id), json!({"scan_type": "baseline_passive"}), &seceng_tok).await;
    assert_eq!(s_sec_scan2, StatusCode::ACCEPTED);
    let scan2: ScanResponse = serde_json::from_slice(&b_sec_scan2).unwrap();

    // 5. Cross-Application Scan Comparison Isolation:
    // Comparing scans belonging to two different applications must be rejected
    let comp_uri = format!("/api/v1/scans/compare?base={}&target={}", scan1.id, scan2.id);
    let (s_comp, b_comp) = harness.client.get_auth(&comp_uri, &admin_tok).await;
    assert_eq!(s_comp, StatusCode::BAD_REQUEST);
    let comp_err: serde_json::Value = serde_json::from_slice(&b_comp).unwrap();
    assert_eq!(comp_err["error"]["code"], "INVALID_INPUT");

    // 6. Admin Role: Successfully manages inventory
    let (s_admin_del, _) = harness.client.delete_auth(&format!("/api/v1/apps/{}", app1.id), &admin_tok).await;
    assert_eq!(s_admin_del, StatusCode::OK);
}

