//! Tier 4: Real-World Scenario 1 - Full SecOps Onboarding & Security Audit Workflow

use axum::http::StatusCode;
use serde_json::json;

use crate::common::*;
use infra::traits::ZapAlert;

#[tokio::test]
async fn test_tier4_scenario_secops_audit_workflow() {
    let harness = IntegratedHarness::new().await;

    // 1. Authenticate as SecOps Admin
    let login_payload = json!({
        "email": "admin@kds.local",
        "password": "AdminSecret123!"
    });
    let (s_login, b_login) = harness.client.post_json("/api/v1/auth/login", login_payload).await;
    assert_eq!(s_login, StatusCode::OK);
    let token_resp: TokenResponse = serde_json::from_slice(&b_login).unwrap();
    let admin_tok = token_resp.access_token;

    // 2. Register Mission-Critical Payment Application
    let app_payload = json!({
        "name": "Global Payments Gateway",
        "description": "PCI-DSS Level 1 payment processing core",
        "base_url": "https://payments.internal.corp",
        "environment": "production",
        "criticality": "critical",
        "team_name": "Fintech Platform",
        "include_regexes": ["https://payments.internal.corp/.*"],
        "exclude_regexes": ["/healthz", "/metrics"],
        "cron_schedule": "0 2 * * *",
        "is_authorized": true
    });
    let (s_app, b_app) = harness.client.post_json_auth("/api/v1/apps", app_payload, &admin_tok).await;
    assert_eq!(s_app, StatusCode::CREATED);
    let app: ApplicationResponse = serde_json::from_slice(&b_app).unwrap();

    // 3. Configure Authenticated Scanning Profile
    let auth_payload = json!({
        "auth_type": "bearer_token",
        "auth_data": {
            "token": "pci_authorized_bearer_sec_token"
        }
    });
    let (s_auth, _) = harness.client.put_json_auth(&format!("/api/v1/apps/{}/auth", app.id), auth_payload, &admin_tok).await;
    assert_eq!(s_auth, StatusCode::OK);

    // 4. Setup Mock ZAP Scanner findings
    let alert = ZapAlert {
        id: "101".to_string(),
        plugin_id: "40018".to_string(),
        alert: "Remote SQL Injection in /checkout/charge".to_string(),
        name: Some("SQL Injection".to_string()),
        risk: "High".to_string(),
        confidence: "High".to_string(),
        url: "https://payments.internal.corp/checkout/charge".to_string(),
        param: Some("card_token".to_string()),
        attack: Some("' OR SLEEP(5)--".to_string()),
        evidence: Some("Response delay detected".to_string()),
        description: "Time-based blind SQL injection in payment processing endpoint".to_string(),
        solution: "Enforce strict parameterized queries".to_string(),
        reference: Some("https://owasp.org/sqli".to_string()),
        cweid: Some("89".to_string()),
        wascid: Some("19".to_string()),
        method: Some("POST".to_string()),
        request_header: None,
        response_header: None,
    };
    harness.mock_zap.set_mock_alerts(vec![alert]).await;

    // 5. Trigger Security Scan
    let scan_req = json!({
        "scan_type": "full_active",
        "max_duration_minutes": 60
    });
    let (s_scan, b_scan) = harness.client.post_json_auth(&format!("/api/v1/apps/{}/scans", app.id), scan_req, &admin_tok).await;
    assert_eq!(s_scan, StatusCode::ACCEPTED);
    let scan: ScanResponse = serde_json::from_slice(&b_scan).unwrap();

    // 6. Background Scan Worker consumes and completes scan
    let executed = harness.scan_engine.poll_and_execute_once().await.unwrap();
    assert_eq!(executed, Some(scan.id));

    // 7. Verify Completed Scan Findings
    let (s_find, b_find) = harness.client.get_auth(&format!("/api/v1/vulns?app_id={}", app.id), &admin_tok).await;
    assert_eq!(s_find, StatusCode::OK);
    let findings: PaginatedResponse<VulnerabilitySummary> = serde_json::from_slice(&b_find).unwrap();
    assert_eq!(findings.total, 1);
    let vuln_id = findings.items[0].id;

    // 8. Security Engineer triages finding and assigns remediation ticket
    let seceng_tok = harness.seceng_token().await;
    let triage_payload = json!({
        "status": "in_progress",
        "severity": "critical",
        "comment": "Escalated to Payment Core team with P0 priority"
    });
    let (s_triage, b_triage) = harness.client.patch_json_auth(&format!("/api/v1/vulns/{}", vuln_id), triage_payload, &seceng_tok).await;
    assert_eq!(s_triage, StatusCode::OK);
    let triaged_vuln: VulnerabilityDetail = serde_json::from_slice(&b_triage).unwrap();
    assert_eq!(triaged_vuln.summary.status, RemediationStatus::InProgress);
    assert_eq!(triaged_vuln.summary.severity, SeverityLevel::Critical);

    // 9. Inspect Dashboard Posture
    let (s_dash, b_dash) = harness.client.get_auth("/api/v1/dashboard/summary", &admin_tok).await;
    assert_eq!(s_dash, StatusCode::OK);
    let dash: serde_json::Value = serde_json::from_slice(&b_dash).unwrap();
    assert_eq!(dash["total_applications"], 1);

    // 10. Export Official Typst Executive PDF Audit Report
    let (s_pdf, b_pdf) = harness.client.get_auth(&format!("/api/v1/reports/scans/{}/pdf", scan.id), &admin_tok).await;
    assert_eq!(s_pdf, StatusCode::OK);
    assert!(b_pdf.starts_with(b"%PDF"), "Must download valid PDF report stream");
}
