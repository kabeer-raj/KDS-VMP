use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::error::InfraError;
use crate::traits::{ZapAlert, ZapClient, ZapContextConfig};

pub struct HttpZapClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl HttpZapClient {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            api_key,
        }
    }

    fn add_api_key(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref key) = self.api_key {
            req = req.header("X-ZAP-API-Key", key);
        }
        req
    }
}

#[async_trait]
impl ZapClient for HttpZapClient {
    async fn start_spider(&self, target_url: &str, context_name: Option<&str>) -> Result<String, InfraError> {
        let url = format!("{}/JSON/spider/action/scan/", self.base_url);
        let mut req = self.client.get(&url).query(&[("url", target_url)]);
        if let Some(ctx) = context_name {
            req = req.query(&[("contextName", ctx)]);
        }
        req = self.add_api_key(req);

        let res = req.send().await?.json::<serde_json::Value>().await?;
        res.get("scan")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| InfraError::Zap("Failed to get spider scan ID".to_string()))
    }

    async fn get_spider_status(&self, scan_id: &str) -> Result<u8, InfraError> {
        let url = format!("{}/JSON/spider/view/status/", self.base_url);
        let req = self.add_api_key(self.client.get(&url).query(&[("scanId", scan_id)]));

        let res = req.send().await?.json::<serde_json::Value>().await?;
        let status_str = res
            .get("status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| InfraError::Zap("Failed to get spider status".to_string()))?;
        status_str
            .parse::<u8>()
            .map_err(|e| InfraError::Zap(format!("Invalid status value: {}", e)))
    }

    async fn start_active_scan(&self, target_url: &str, context_name: Option<&str>) -> Result<String, InfraError> {
        let url = format!("{}/JSON/ascan/action/scan/", self.base_url);
        let mut req = self.client.get(&url).query(&[("url", target_url)]);
        if let Some(ctx) = context_name {
            req = req.query(&[("contextName", ctx)]);
        }
        req = self.add_api_key(req);

        let res = req.send().await?.json::<serde_json::Value>().await?;
        res.get("scan")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| InfraError::Zap("Failed to get active scan ID".to_string()))
    }

    async fn get_active_scan_status(&self, scan_id: &str) -> Result<u8, InfraError> {
        let url = format!("{}/JSON/ascan/view/status/", self.base_url);
        let req = self.add_api_key(self.client.get(&url).query(&[("scanId", scan_id)]));

        let res = req.send().await?.json::<serde_json::Value>().await?;
        let status_str = res
            .get("status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| InfraError::Zap("Failed to get active scan status".to_string()))?;
        status_str
            .parse::<u8>()
            .map_err(|e| InfraError::Zap(format!("Invalid status value: {}", e)))
    }

    async fn get_alerts(&self, base_url: &str, start: Option<u32>, count: Option<u32>) -> Result<Vec<ZapAlert>, InfraError> {
        let url = format!("{}/JSON/core/view/alerts/", self.base_url);
        let mut req = self.client.get(&url).query(&[("baseurl", base_url)]);
        if let Some(s) = start {
            req = req.query(&[("start", s.to_string())]);
        }
        if let Some(c) = count {
            req = req.query(&[("count", c.to_string())]);
        }
        req = self.add_api_key(req);

        let res = req.send().await?.json::<serde_json::Value>().await?;
        if let Some(alerts_val) = res.get("alerts") {
            let alerts: Vec<ZapAlert> = serde_json::from_value(alerts_val.clone())?;
            Ok(alerts)
        } else {
            Ok(Vec::new())
        }
    }

    async fn configure_context(&self, context: &ZapContextConfig) -> Result<String, InfraError> {
        let new_ctx_url = format!("{}/JSON/context/action/newContext/", self.base_url);
        let req = self.add_api_key(
            self.client
                .get(&new_ctx_url)
                .query(&[("contextName", &context.context_name)]),
        );
        let res = req.send().await?.json::<serde_json::Value>().await?;
        let context_id = res
            .get("contextId")
            .and_then(|v| v.as_str())
            .unwrap_or("1")
            .to_string();

        for regex in &context.include_regexes {
            let inc_url = format!("{}/JSON/context/action/includeInContext/", self.base_url);
            let req = self.add_api_key(
                self.client
                    .get(&inc_url)
                    .query(&[("contextName", &context.context_name), ("regex", regex)]),
            );
            let _ = req.send().await;
        }

        for regex in &context.exclude_regexes {
            let exc_url = format!("{}/JSON/context/action/excludeFromContext/", self.base_url);
            let req = self.add_api_key(
                self.client
                    .get(&exc_url)
                    .query(&[("contextName", &context.context_name), ("regex", regex)]),
            );
            let _ = req.send().await;
        }

        Ok(context_id)
    }
}

pub struct MockZapClient {
    contexts: RwLock<HashMap<String, ZapContextConfig>>,
    spider_scans: RwLock<HashMap<String, u8>>,
    active_scans: RwLock<HashMap<String, u8>>,
    alerts: RwLock<Vec<ZapAlert>>,
}

impl MockZapClient {
    pub fn new() -> Self {
        let default_alerts = vec![
            ZapAlert {
                id: "1".to_string(),
                plugin_id: "40018".to_string(),
                alert: "SQL Injection".to_string(),
                name: Some("SQL Injection".to_string()),
                risk: "High".to_string(),
                confidence: "High".to_string(),
                url: "https://example.com/api/users".to_string(),
                param: Some("id".to_string()),
                attack: Some("' OR '1'='1".to_string()),
                evidence: Some("syntax error near SELECT".to_string()),
                description: "SQL Injection vulnerability".to_string(),
                solution: "Use prepared statements".to_string(),
                reference: Some("https://owasp.org/sqli".to_string()),
                cweid: Some("89".to_string()),
                wascid: Some("19".to_string()),
                method: Some("GET".to_string()),
                request_header: Some("GET /api/users?id=1 HTTP/1.1".to_string()),
                response_header: Some("HTTP/1.1 500 Internal Server Error".to_string()),
            },
            ZapAlert {
                id: "2".to_string(),
                plugin_id: "40012".to_string(),
                alert: "Cross Site Scripting (Reflected)".to_string(),
                name: Some("Reflected XSS".to_string()),
                risk: "Medium".to_string(),
                confidence: "Medium".to_string(),
                url: "https://example.com/search".to_string(),
                param: Some("q".to_string()),
                attack: Some("<script>alert(1)</script>".to_string()),
                evidence: Some("<script>alert(1)</script>".to_string()),
                description: "XSS vulnerability".to_string(),
                solution: "Encode user input".to_string(),
                reference: Some("https://owasp.org/xss".to_string()),
                cweid: Some("79".to_string()),
                wascid: Some("8".to_string()),
                method: Some("GET".to_string()),
                request_header: None,
                response_header: None,
            },
        ];

        Self {
            contexts: RwLock::new(HashMap::new()),
            spider_scans: RwLock::new(HashMap::new()),
            active_scans: RwLock::new(HashMap::new()),
            alerts: RwLock::new(default_alerts),
        }
    }

    pub async fn set_mock_alerts(&self, alerts: Vec<ZapAlert>) {
        let mut alert_guard = self.alerts.write().await;
        *alert_guard = alerts;
    }
}

impl Default for MockZapClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ZapClient for MockZapClient {
    async fn start_spider(&self, _target_url: &str, _context_name: Option<&str>) -> Result<String, InfraError> {
        let id = "mock_spider_1".to_string();
        let mut scans = self.spider_scans.write().await;
        scans.insert(id.clone(), 100);
        Ok(id)
    }

    async fn get_spider_status(&self, scan_id: &str) -> Result<u8, InfraError> {
        let scans = self.spider_scans.read().await;
        Ok(scans.get(scan_id).copied().unwrap_or(100))
    }

    async fn start_active_scan(&self, _target_url: &str, _context_name: Option<&str>) -> Result<String, InfraError> {
        let id = "mock_ascan_1".to_string();
        let mut scans = self.active_scans.write().await;
        scans.insert(id.clone(), 100);
        Ok(id)
    }

    async fn get_active_scan_status(&self, scan_id: &str) -> Result<u8, InfraError> {
        let scans = self.active_scans.read().await;
        Ok(scans.get(scan_id).copied().unwrap_or(100))
    }

    async fn get_alerts(&self, _base_url: &str, _start: Option<u32>, _count: Option<u32>) -> Result<Vec<ZapAlert>, InfraError> {
        let alerts = self.alerts.read().await;
        Ok(alerts.clone())
    }

    async fn configure_context(&self, context: &ZapContextConfig) -> Result<String, InfraError> {
        let id = "mock_ctx_1".to_string();
        let mut contexts = self.contexts.write().await;
        contexts.insert(context.context_name.clone(), context.clone());
        Ok(id)
    }
}
