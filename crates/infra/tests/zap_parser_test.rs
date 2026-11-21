use infra::traits::{ZapAlert, ZapClient, ZapContextConfig};
use infra::zap::{MockZapClient, ZapAlertParser};
use shared_types::SeverityLevel;
use uuid::Uuid;

#[test]
fn test_zap_alert_deserialization_and_parsing() {
    let json_data = r#"[
        {
            "id": "1",
            "pluginId": "40018",
            "alert": "SQL Injection",
            "risk": "High",
            "confidence": "Medium",
            "url": "https://api.example.com/v1/users?id=1",
            "param": "id",
            "attack": "1' OR '1'='1",
            "evidence": "syntax error in SQL statement",
            "description": "SQL injection vulnerability detected.",
            "solution": "Use parameterized queries.",
            "reference": "https://owasp.org/sqli\nhttps://cwe.mitre.org/data/definitions/89.html",
            "cweid": "89",
            "wascid": "19",
            "method": "GET",
            "requestHeader": "GET /v1/users?id=1 HTTP/1.1",
            "responseHeader": "HTTP/1.1 500 Internal Server Error"
        },
        {
            "id": "2",
            "pluginId": "10020",
            "alert": "Missing Anti-clickjacking Header",
            "risk": "Medium",
            "confidence": "High",
            "url": "https://api.example.com/",
            "param": "",
            "attack": "",
            "evidence": "X-Frame-Options header missing",
            "description": "The response does not include X-Frame-Options header.",
            "solution": "Set X-Frame-Options to DENY or SAMEORIGIN.",
            "reference": "https://owasp.org/clickjacking",
            "cweid": "1021",
            "wascid": "15",
            "method": "GET"
        }
    ]"#;

    let alerts: Vec<ZapAlert> = serde_json::from_str(json_data).expect("failed to deserialize zap alerts");
    assert_eq!(alerts.len(), 2);

    let app_id = Uuid::new_v4();
    let findings = ZapAlertParser::parse_alerts(&alerts, &app_id);
    assert_eq!(findings.len(), 2);

    // SQLi assertion
    let f1 = &findings[0];
    assert_eq!(f1.zap_plugin_id, "40018");
    assert_eq!(f1.title, "SQL Injection");
    assert_eq!(f1.cwe_id, Some(89));
    assert_eq!(f1.wasc_id, Some(19));
    assert_eq!(f1.severity, Some(SeverityLevel::High));
    assert_eq!(f1.http_method, "GET");
    assert_eq!(f1.affected_param, Some("id".to_string()));
    assert_eq!(f1.attack_payload, Some("1' OR '1'='1".to_string()));
    assert_eq!(f1.reference_urls.len(), 2);

    // Missing header assertion
    let f2 = &findings[1];
    assert_eq!(f2.zap_plugin_id, "10020");
    assert_eq!(f2.severity, Some(SeverityLevel::Medium));
    assert_eq!(f2.cwe_id, Some(1021));
    assert!(f2.affected_param.is_none());
}

#[tokio::test]
async fn test_mock_zap_client() {
    let mock = MockZapClient::new();
    let target = "https://example.com";

    let context = ZapContextConfig {
        context_name: "Test Context".to_string(),
        target_url: target.to_string(),
        include_regexes: vec!["https://example.com/.*".to_string()],
        exclude_regexes: vec![],
        auth_header: None,
        session_cookie: None,
    };

    let ctx_id = mock.configure_context(&context).await.expect("config context failed");
    assert!(!ctx_id.is_empty());

    let spider_id = mock.start_spider(target, Some("Test Context")).await.expect("start spider failed");
    let spider_status = mock.get_spider_status(&spider_id).await.expect("spider status failed");
    assert!(spider_status <= 100);

    let ascan_id = mock.start_active_scan(target, Some("Test Context")).await.expect("start ascan failed");
    let ascan_status = mock.get_active_scan_status(&ascan_id).await.expect("ascan status failed");
    assert!(ascan_status <= 100);

    let alerts = mock.get_alerts(target, Some(0), Some(10)).await.expect("get alerts failed");
    assert!(!alerts.is_empty());
}
