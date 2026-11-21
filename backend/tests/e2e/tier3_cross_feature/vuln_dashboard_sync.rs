//! Tier 3: Cross-Feature Combinations - Background Scan Execution & Dashboard Sync

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::*;
use infra::traits::{PubSubPort, ZapAlert};

#[tokio::test]
async fn test_tier3_background_scan_engine_pipeline_and_dashboard_update() {
    let harness = IntegratedHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let app = harness.seed_application("Sync Target App", "https://sync.internal", true).await;

    // 1. Configure Mock ZAP with realistic alerts
    let alerts = vec![
        ZapAlert {
            id: "1".to_string(),
            plugin_id: "40018".to_string(),
            alert: "SQL Injection".to_string(),
            name: Some("SQL Injection".to_string()),
            risk: "High".to_string(),
            confidence: "High".to_string(),
            url: "https://sync.internal/api/orders".to_string(),
            param: Some("order_id".to_string()),
            attack: Some("1 OR 1=1".to_string()),
            evidence: Some("SQL syntax error".to_string()),
            description: "SQL Injection in orders endpoint".to_string(),
            solution: "Use ORM or parameterized queries".to_string(),
            reference: Some("https://owasp.org/sqli".to_string()),
            cweid: Some("89".to_string()),
            wascid: Some("19".to_string()),
            method: Some("GET".to_string()),
            request_header: None,
            response_header: None,
        },
        ZapAlert {
            id: "2".to_string(),
            plugin_id: "40012".to_string(),
            alert: "Reflected XSS".to_string(),
            name: Some("Reflected XSS".to_string()),
            risk: "Medium".to_string(),
            confidence: "High".to_string(),
            url: "https://sync.internal/search".to_string(),
            param: Some("q".to_string()),
            attack: Some("<script>alert(1)</script>".to_string()),
            evidence: Some("<script>alert(1)</script>".to_string()),
            description: "XSS in search query".to_string(),
            solution: "HTML entity encoding".to_string(),
            reference: Some("https://owasp.org/xss".to_string()),
            cweid: Some("79".to_string()),
            wascid: Some("8".to_string()),
            method: Some("GET".to_string()),
            request_header: None,
            response_header: None,
        },
    ];
    harness.mock_zap.set_mock_alerts(alerts).await;

    // 2. Subscribe to PubSub progress stream
    let mut rx = harness.pubsub.subscribe_scan_progress(Uuid::nil()).await.unwrap();

    // 3. Trigger scan via REST API
    let trigger_payload = json!({
        "scan_type": "full_active"
    });
    let (s_trig, b_trig) = harness.client.post_json_auth(&format!("/api/v1/apps/{}/scans", app.id), trigger_payload, &admin_tok).await;
    assert_eq!(s_trig, StatusCode::ACCEPTED);
    let queued_scan: ScanResponse = serde_json::from_slice(&b_trig).unwrap();

    // 4. Background ScanWorkerEngine consumes and executes the queued scan
    let executed_scan_id = harness.scan_engine.poll_and_execute_once().await.unwrap();
    assert_eq!(executed_scan_id, Some(queued_scan.id));

    // 5. Verify live events were broadcast
    let mut received_progress = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, WsServerEvent::ScanProgress { .. } | WsServerEvent::ScanCompleted { .. }) {
            received_progress = true;
            break;
        }
    }
    assert!(received_progress, "PubSub should receive live scan events");

    // 6. Verify scan status via REST API is now Completed with counts
    let (s_scan, b_scan) = harness.client.get_auth(&format!("/api/v1/scans/{}", queued_scan.id), &admin_tok).await;
    assert_eq!(s_scan, StatusCode::OK);
    let completed_scan: ScanResponse = serde_json::from_slice(&b_scan).unwrap();
    assert_eq!(completed_scan.status, ScanStatus::Completed);
    assert_eq!(completed_scan.progress_percent, 100);
    assert!(completed_scan.severity_counts.high >= 1);
    assert!(completed_scan.severity_counts.medium >= 1);

    // 7. Verify dashboard summary is immediately updated
    let (s_dash, b_dash) = harness.client.get_auth("/api/v1/dashboard/summary", &admin_tok).await;
    assert_eq!(s_dash, StatusCode::OK);
    let dash: serde_json::Value = serde_json::from_slice(&b_dash).unwrap();
    assert_eq!(dash["total_applications"], 1);
    assert!(dash["total_vulnerabilities"].as_u64().unwrap() >= 2);

    // 8. Verify PDF report compiles cleanly
    let (s_pdf, b_pdf) = harness.client.get_auth(&format!("/api/v1/reports/scans/{}/pdf", queued_scan.id), &admin_tok).await;
    assert_eq!(s_pdf, StatusCode::OK);
    assert!(b_pdf.starts_with(b"%PDF"));
}
