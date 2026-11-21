use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZapRawAlert {
    #[serde(rename = "pluginId", default)]
    pub plugin_id: String,
    #[serde(rename = "alert", default)]
    pub alert: String,
    #[serde(rename = "name", default)]
    pub name: Option<String>,
    #[serde(rename = "risk", default)]
    pub risk: String,
    #[serde(rename = "confidence", default)]
    pub confidence: String,
    #[serde(rename = "url", default)]
    pub url: String,
    #[serde(rename = "param", default)]
    pub param: String,
    #[serde(rename = "attack", default)]
    pub attack: String,
    #[serde(rename = "evidence", default)]
    pub evidence: String,
    #[serde(rename = "description", default)]
    pub description: String,
    #[serde(rename = "solution", default)]
    pub solution: String,
    #[serde(rename = "reference", default)]
    pub reference: String,
    #[serde(rename = "cweid", default)]
    pub cweid: String,
    #[serde(rename = "wascid", default)]
    pub wascid: String,
    #[serde(rename = "method", default)]
    pub method: String,
    #[serde(rename = "requestHeader", default)]
    pub request_header: Option<String>,
    #[serde(rename = "responseHeader", default)]
    pub response_header: Option<String>,
}

#[derive(Clone, Default)]
pub struct MockZapClient {
    alerts: Arc<RwLock<HashMap<String, Vec<ZapRawAlert>>>>,
}

impl MockZapClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set_alerts(&self, target_key: &str, alerts: Vec<ZapRawAlert>) {
        let mut map = self.alerts.write().await;
        map.insert(target_key.to_string(), alerts);
    }

    pub async fn get_alerts(&self, target_key: &str) -> Vec<ZapRawAlert> {
        let map = self.alerts.read().await;
        map.get(target_key).cloned().unwrap_or_default()
    }

    pub async fn clear_alerts(&self) {
        let mut map = self.alerts.write().await;
        map.clear();
    }
}

pub struct AlertFixtureFactory;

impl AlertFixtureFactory {
    pub fn sqli_alert(base_url: &str) -> ZapRawAlert {
        ZapRawAlert {
            plugin_id: "40018".to_string(),
            alert: "SQL Injection".to_string(),
            name: Some("SQL Injection".to_string()),
            risk: "High".to_string(),
            confidence: "High".to_string(),
            url: format!("{}/api/v1/users", base_url.trim_end_matches('/')),
            param: "id".to_string(),
            attack: "1' OR '1'='1".to_string(),
            evidence: "syntax error at or near 'OR'".to_string(),
            description: "SQL injection allows attackers to manipulate backend database queries.".to_string(),
            solution: "Use parameterized queries or ORM prepared statements.".to_string(),
            reference: "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
            cweid: "89".to_string(),
            wascid: "19".to_string(),
            method: "GET".to_string(),
            request_header: Some("GET /api/v1/users?id=1' OR '1'='1 HTTP/1.1".to_string()),
            response_header: Some("HTTP/1.1 500 Internal Server Error".to_string()),
        }
    }

    pub fn xss_alert(base_url: &str) -> ZapRawAlert {
        ZapRawAlert {
            plugin_id: "40012".to_string(),
            alert: "Cross Site Scripting (Reflected)".to_string(),
            name: Some("Cross Site Scripting (Reflected)".to_string()),
            risk: "Medium".to_string(),
            confidence: "High".to_string(),
            url: format!("{}/search", base_url.trim_end_matches('/')),
            param: "q".to_string(),
            attack: "<script>alert(1)</script>".to_string(),
            evidence: "<script>alert(1)</script>".to_string(),
            description: "Reflected XSS occurs when untrusted user input is returned in HTTP response.".to_string(),
            solution: "Apply context-sensitive output encoding and HTML sanitization.".to_string(),
            reference: "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
            cweid: "79".to_string(),
            wascid: "8".to_string(),
            method: "GET".to_string(),
            request_header: Some("GET /search?q=<script>alert(1)</script> HTTP/1.1".to_string()),
            response_header: Some("HTTP/1.1 200 OK".to_string()),
        }
    }

    pub fn csrf_alert(base_url: &str) -> ZapRawAlert {
        ZapRawAlert {
            plugin_id: "40026".to_string(),
            alert: "Absence of Anti-CSRF Tokens".to_string(),
            name: Some("Absence of Anti-CSRF Tokens".to_string()),
            risk: "Medium".to_string(),
            confidence: "Medium".to_string(),
            url: format!("{}/account/update-email", base_url.trim_end_matches('/')),
            param: "".to_string(),
            attack: "".to_string(),
            evidence: "".to_string(),
            description: "No Anti-CSRF tokens detected in sensitive state-changing POST request.".to_string(),
            solution: "Implement Anti-CSRF tokens and SameSite cookie policies.".to_string(),
            reference: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/".to_string(),
            cweid: "352".to_string(),
            wascid: "9".to_string(),
            method: "POST".to_string(),
            request_header: Some("POST /account/update-email HTTP/1.1".to_string()),
            response_header: Some("HTTP/1.1 200 OK".to_string()),
        }
    }

    pub fn csp_alert(base_url: &str) -> ZapRawAlert {
        ZapRawAlert {
            plugin_id: "10038".to_string(),
            alert: "Content Security Policy (CSP) Header Not Set".to_string(),
            name: Some("CSP Header Not Set".to_string()),
            risk: "Low".to_string(),
            confidence: "High".to_string(),
            url: format!("{}/index.html", base_url.trim_end_matches('/')),
            param: "".to_string(),
            attack: "".to_string(),
            evidence: "".to_string(),
            description: "Content Security Policy header is not present in response.".to_string(),
            solution: "Configure a robust Content-Security-Policy HTTP header.".to_string(),
            reference: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
            cweid: "16".to_string(),
            wascid: "15".to_string(),
            method: "GET".to_string(),
            request_header: Some("GET /index.html HTTP/1.1".to_string()),
            response_header: Some("HTTP/1.1 200 OK".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_zap_client_storage() {
        let client = MockZapClient::new();
        let target = "https://example.com";
        let sqli = AlertFixtureFactory::sqli_alert(target);
        let xss = AlertFixtureFactory::xss_alert(target);

        client.set_alerts(target, vec![sqli.clone(), xss.clone()]).await;
        let retrieved = client.get_alerts(target).await;
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved[0].plugin_id, "40018");
        assert_eq!(retrieved[1].plugin_id, "40012");

        client.clear_alerts().await;
        let empty = client.get_alerts(target).await;
        assert!(empty.is_empty());
    }

    #[test]
    fn test_alert_fixtures_serialization() {
        let base_url = "https://api.payments.internal";
        let fixtures = [
            AlertFixtureFactory::sqli_alert(base_url),
            AlertFixtureFactory::xss_alert(base_url),
            AlertFixtureFactory::csrf_alert(base_url),
            AlertFixtureFactory::csp_alert(base_url),
        ];

        for alert in fixtures {
            let json = serde_json::to_string(&alert).expect("Must serialize to JSON");
            let parsed: ZapRawAlert = serde_json::from_str(&json).expect("Must deserialize from JSON");
            assert_eq!(parsed, alert);
        }
    }
}
